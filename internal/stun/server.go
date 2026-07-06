package stun

import (
	"context"
	"log"
	"net"
	"net/netip"
)

// Serve répond aux requêtes Binding sur pc jusqu'à annulation du contexte.
// Chaque réponse porte l'adresse source observée du client — c'est ainsi
// qu'une machine derrière NAT découvre son endpoint public.
func Serve(ctx context.Context, pc net.PacketConn) error {
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		id, err := ParseBindingRequest(buf[:n])
		if err != nil {
			continue // pas une requête STUN : on ignore
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := netip.AddrPortFrom(udpAddr.AddrPort().Addr().Unmap(), udpAddr.AddrPort().Port())
		if _, err := pc.WriteTo(BuildBindingResponse(id, ap), addr); err != nil {
			log.Printf("stun: réponse à %s: %v", addr, err)
		}
	}
}
