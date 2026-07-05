package relay

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// clientTTL : durée de validité d'un enregistrement sans nouveau REGISTER
// (les clients ré-enregistrent à chaque cycle de synchronisation, ~10 s).
const clientTTL = 40 * time.Second

// maxPacket dimensionne le tampon de lecture (MTU tunnel + en-têtes).
const maxPacket = 2048

type client struct {
	addr     netip.AddrPort
	lastSeen time.Time
}

// Server fait suivre les trames entre clients enregistrés.
type Server struct {
	mu      sync.Mutex
	clients map[[keyLen]byte]client
	byAddr  map[netip.AddrPort][keyLen]byte
}

// Serve traite les trames sur pc jusqu'à annulation du contexte.
func Serve(ctx context.Context, pc net.PacketConn) error {
	s := &Server{
		clients: map[[keyLen]byte]client{},
		byAddr:  map[netip.AddrPort][keyLen]byte{},
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, maxPacket)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		src := netip.AddrPortFrom(udpAddr.AddrPort().Addr().Unmap(), udpAddr.AddrPort().Port())
		s.handle(pc, buf[:n], src)
	}
}

func (s *Server) handle(pc net.PacketConn, pkt []byte, src netip.AddrPort) {
	if !IsFrame(pkt) {
		return
	}
	switch FrameType(pkt) {
	case TypeRegister:
		key, _, ok := ParseKeyed(pkt)
		if !ok {
			return
		}
		s.mu.Lock()
		if old, exists := s.clients[key]; exists && old.addr != src {
			delete(s.byAddr, old.addr)
		}
		s.clients[key] = client{addr: src, lastSeen: time.Now()}
		s.byAddr[src] = key
		s.mu.Unlock()
		_, _ = pc.WriteTo(BuildAck(), net.UDPAddrFromAddrPort(src))

	case TypeForward:
		dstKey, payload, ok := ParseKeyed(pkt)
		if !ok || len(payload) == 0 {
			return
		}
		s.mu.Lock()
		srcKey, senderKnown := s.byAddr[src]
		dst, dstKnown := s.clients[dstKey]
		fresh := dstKnown && time.Since(dst.lastSeen) < clientTTL
		s.mu.Unlock()
		// L'expéditeur doit être enregistré : la trame RECV porte sa clé,
		// et un inconnu ne doit pas pouvoir injecter du trafic attribué.
		if !senderKnown || !fresh {
			return
		}
		_, _ = pc.WriteTo(BuildRecv(srcKey, payload), net.UDPAddrFromAddrPort(dst.addr))
	}
}
