package relay

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// clientTTL : durée de validité d'un enregistrement sans nouveau REGISTER
// (les clients ré-enregistrent à chaque cycle de synchronisation, ~10 s).
const clientTTL = 40 * time.Second

// challengeTTL : durée de validité d'un défi en attente de preuve.
const challengeTTL = 30 * time.Second

// maxPacket dimensionne le tampon de lecture (MTU tunnel + en-têtes).
const maxPacket = 2048

type client struct {
	addr     netip.AddrPort
	lastSeen time.Time
}

type pendingChallenge struct {
	nonce   [nonceLen]byte
	expires time.Time
}

// Server fait suivre les trames entre clients authentifiés.
type Server struct {
	priv [keyLen]byte
	pub  [keyLen]byte

	mu       sync.Mutex
	clients  map[[keyLen]byte]client
	byAddr   map[netip.AddrPort][keyLen]byte
	pending  map[netip.AddrPort]pendingChallenge
}

// Serve traite les trames sur pc jusqu'à annulation du contexte. Le relais
// génère une paire de clés Curve25519 éphémère pour les défis-réponses.
func Serve(ctx context.Context, pc net.PacketConn) error {
	s := &Server{
		clients: map[[keyLen]byte]client{},
		byAddr:  map[netip.AddrPort][keyLen]byte{},
		pending: map[netip.AddrPort]pendingChallenge{},
	}
	if _, err := rand.Read(s.priv[:]); err != nil {
		return fmt.Errorf("génération de la clé du relais: %w", err)
	}
	pub, err := curve25519.X25519(s.priv[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	copy(s.pub[:], pub)

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
		// Rafraîchissement d'un enregistrement encore valide, même clé et
		// même adresse : pas besoin de re-prouver.
		if cur, exists := s.clients[key]; exists && cur.addr == src &&
			time.Since(cur.lastSeen) < clientTTL {
			s.clients[key] = client{addr: src, lastSeen: time.Now()}
			s.mu.Unlock()
			_, _ = pc.WriteTo(BuildAck(), net.UDPAddrFromAddrPort(src))
			return
		}
		// Nouvel enregistrement (ou adresse changée) : défi.
		var ch pendingChallenge
		if _, err := rand.Read(ch.nonce[:]); err != nil {
			s.mu.Unlock()
			return
		}
		ch.expires = time.Now().Add(challengeTTL)
		s.pending[src] = ch
		s.mu.Unlock()
		_, _ = pc.WriteTo(BuildChallenge(s.pub, ch.nonce), net.UDPAddrFromAddrPort(src))

	case TypeProof:
		clientPub, nonce, mac, ok := ParseProof(pkt)
		if !ok {
			return
		}
		s.mu.Lock()
		ch, exists := s.pending[src]
		valid := exists && time.Now().Before(ch.expires) && ch.nonce == nonce
		if valid {
			delete(s.pending, src)
		}
		s.mu.Unlock()
		if !valid || !VerifyProof(s.priv, clientPub, nonce, mac) {
			return
		}
		s.mu.Lock()
		if old, exists := s.clients[clientPub]; exists && old.addr != src {
			delete(s.byAddr, old.addr)
		}
		s.clients[clientPub] = client{addr: src, lastSeen: time.Now()}
		s.byAddr[src] = clientPub
		s.mu.Unlock()
		_, _ = pc.WriteTo(BuildAck(), net.UDPAddrFromAddrPort(src))

	case TypeForward:
		dstKey, payload, ok := ParseKeyed(pkt)
		if !ok || len(payload) == 0 {
			return
		}
		s.mu.Lock()
		srcKey, senderKnown := s.byAddr[src]
		sender := s.clients[srcKey]
		dst, dstKnown := s.clients[dstKey]
		fresh := dstKnown && time.Since(dst.lastSeen) < clientTTL
		s.mu.Unlock()
		// L'expéditeur doit être authentifié et à jour : la trame RECV
		// porte sa clé, et un inconnu ne doit pas pouvoir injecter du
		// trafic attribué à autrui.
		if !senderKnown || sender.addr != src || time.Since(sender.lastSeen) >= clientTTL || !fresh {
			return
		}
		_, _ = pc.WriteTo(BuildRecv(srcKey, payload), net.UDPAddrFromAddrPort(dst.addr))
	}
}
