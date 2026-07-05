// Package omnisock fournit la « socket magique » de l'agent : une
// implémentation de conn.Bind (wireguard-go) qui partage une unique socket
// UDP entre trois protocoles, démultiplexés à la réception :
//
//   - les paquets WireGuard, remis au moteur wireguard-go ;
//   - les réponses STUN, pour découvrir l'endpoint public du port WireGuard
//     lui-même (indispensable : le mapping NAT dépend du port source) ;
//   - les sondes « disco » ping/pong, pour tester les candidats d'un pair
//     et percer les NAT.
//
// C'est le même principe que le magicsock de Tailscale, en miniature.
package omnisock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/stun"
)

// PongHandler est appelée à la réception d'un pong disco.
type PongHandler func(id DiscoTxID, from netip.AddrPort)

// Bind implémente conn.Bind au-dessus d'une unique socket UDP.
type Bind struct {
	mu       sync.Mutex
	udp      *net.UDPConn
	stunTx   map[stun.TxID]chan netip.AddrPort
	onPong   PongHandler
	closed   bool
}

var _ conn.Bind = (*Bind)(nil)

// New crée un Bind non ouvert (wireguard-go appelle Open au démarrage).
func New() *Bind {
	return &Bind{stunTx: map[stun.TxID]chan netip.AddrPort{}}
}

// SetPongHandler installe le rappel invoqué pour chaque pong disco reçu.
// À appeler avant que le trafic ne circule.
func (b *Bind) SetPongHandler(h PongHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onPong = h
}

// Open implémente conn.Bind.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.udp = udp
	b.closed = false
	actual := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

// receive lit la socket et ne remet à wireguard-go que ses propres paquets ;
// STUN et disco sont traités ici même.
func (b *Bind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	udp := b.conn()
	if udp == nil {
		return 0, net.ErrClosed
	}
	for {
		n, addr, err := udp.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			return 0, err
		}
		src := netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		pkt := bufs[0][:n]

		switch {
		case isDisco(pkt):
			b.handleDisco(pkt, src)
		case stun.IsBindingResponse(pkt):
			b.handleSTUN(pkt)
		default:
			sizes[0] = n
			eps[0] = &endpoint{ap: src}
			return 1, nil
		}
	}
}

func (b *Bind) handleDisco(pkt []byte, src netip.AddrPort) {
	msgType, id := decodeDisco(pkt)
	switch msgType {
	case discoPing:
		// Répondre atteste au pair que ce chemin fonctionne — et le
		// simple envoi maintient/ouvre notre mapping NAT vers lui.
		_ = b.writeTo(encodeDisco(discoPong, id), src)
	case discoPong:
		b.mu.Lock()
		h := b.onPong
		b.mu.Unlock()
		if h != nil {
			h(id, src)
		}
	}
}

func (b *Bind) handleSTUN(pkt []byte) {
	id, mapped, err := stun.ParseBindingResponse(pkt)
	if err != nil {
		return
	}
	b.mu.Lock()
	ch := b.stunTx[id]
	delete(b.stunTx, id)
	b.mu.Unlock()
	if ch != nil {
		ch <- mapped
	}
}

// SendPing émet une sonde disco vers dst et renvoie son identifiant.
func (b *Bind) SendPing(dst netip.AddrPort) (DiscoTxID, error) {
	id := NewDiscoTxID()
	return id, b.writeTo(encodeDisco(discoPing, id), dst)
}

// STUNRequest interroge un serveur STUN à travers la socket WireGuard et
// renvoie l'adresse publique observée pour ce port.
func (b *Bind) STUNRequest(ctx context.Context, server string) (netip.AddrPort, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("serveur stun %q: %w", server, err)
	}
	dst := netip.AddrPortFrom(udpAddr.AddrPort().Addr().Unmap(), udpAddr.AddrPort().Port())

	id := stun.NewTxID()
	ch := make(chan netip.AddrPort, 1)
	b.mu.Lock()
	b.stunTx[id] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.stunTx, id)
		b.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Retransmission simple : le paquet initial peut se perdre.
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()
	if err := b.writeTo(stun.BuildBindingRequest(id), dst); err != nil {
		return netip.AddrPort{}, err
	}
	for {
		select {
		case mapped := <-ch:
			return mapped, nil
		case <-ticker.C:
			_ = b.writeTo(stun.BuildBindingRequest(id), dst)
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		}
	}
}

// LocalPort renvoie le port UDP réellement lié (0 si non ouvert).
func (b *Bind) LocalPort() int {
	udp := b.conn()
	if udp == nil {
		return 0
	}
	return udp.LocalAddr().(*net.UDPAddr).Port
}

func (b *Bind) conn() *net.UDPConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.udp
}

func (b *Bind) writeTo(pkt []byte, dst netip.AddrPort) error {
	udp := b.conn()
	if udp == nil {
		return net.ErrClosed
	}
	_, err := udp.WriteToUDPAddrPort(pkt, dst)
	return err
}

// Close implémente conn.Bind.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.udp == nil {
		return nil
	}
	err := b.udp.Close()
	b.udp = nil
	return err
}

// SetMark implémente conn.Bind (non utilisé sous Linux sans fwmark).
func (b *Bind) SetMark(uint32) error { return nil }

// BatchSize implémente conn.Bind : un paquet par lecture.
func (b *Bind) BatchSize() int { return 1 }

// Send implémente conn.Bind.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return errors.New("endpoint d'un autre bind")
	}
	for _, buf := range bufs {
		if err := b.writeTo(buf, e.ap); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint implémente conn.Bind.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	ap := udpAddr.AddrPort()
	return &endpoint{ap: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

// endpoint implémente conn.Endpoint (adresse de destination seule).
type endpoint struct{ ap netip.AddrPort }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *endpoint) DstIP() netip.Addr   { return e.ap.Addr() }
func (e *endpoint) DstToString() string { return e.ap.String() }
func (e *endpoint) DstToBytes() []byte {
	b, _ := e.ap.MarshalBinary()
	return b
}
