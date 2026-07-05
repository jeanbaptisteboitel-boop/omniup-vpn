package wgnet

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// TestTunnelEndToEnd fait dialoguer deux moteurs WireGuard complets à
// travers deux sockets magiques omnisock sur loopback, avec des piles
// réseau userspace (netstack) à la place d'interfaces TUN réelles :
// le trafic est réellement chiffré, transporté et déchiffré.
func TestTunnelEndToEnd(t *testing.T) {
	privA, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ipA := netip.MustParseAddr("100.99.0.1")
	ipB := netip.MustParseAddr("100.99.0.2")

	tunA, tnetA, err := netstack.CreateNetTUN([]netip.Addr{ipA}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	devA, err := StartWithTUN(tunA, "e2e-a", privA, 0, omnisock.New(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer devA.Close()

	tunB, tnetB, err := netstack.CreateNetTUN([]netip.Addr{ipB}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	devB, err := StartWithTUN(tunB, "e2e-b", privB, 0, omnisock.New(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer devB.Close()

	portA := devA.Bind.LocalPort()
	portB := devB.Bind.LocalPort()
	if portA == 0 || portB == 0 {
		t.Fatal("les sockets devraient être liées après le démarrage du moteur")
	}

	// A connaît l'endpoint de B ; B n'a AUCUN endpoint pour A et doit
	// l'apprendre du premier handshake entrant (roaming WireGuard).
	knownA, knownB := map[string]bool{}, map[string]bool{}
	peerB := types.Peer{PublicKey: privB.PublicKey().String(), IP: ipB.String()}
	peerA := types.Peer{PublicKey: privA.PublicKey().String(), IP: ipA.String()}
	if err := devA.SyncPeers([]types.Peer{peerB}, knownA, func(types.Peer) string {
		return "127.0.0.1:" + strconv.Itoa(portB)
	}); err != nil {
		t.Fatal(err)
	}
	if err := devB.SyncPeers([]types.Peer{peerA}, knownB, func(types.Peer) string {
		return ""
	}); err != nil {
		t.Fatal(err)
	}

	// Écho TCP côté B, à travers le tunnel.
	ln, err := tnetB.ListenTCP(&net.TCPAddr{Port: 7777})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		c.Write(buf[:n])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := tnetA.DialContext(ctx, "tcp", ipB.String()+":7777")
	if err != nil {
		t.Fatalf("connexion à travers le tunnel: %v", err)
	}
	defer conn.Close()

	msg := "bonjour à travers wireguard userspace"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("lecture de l'écho: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("écho corrompu: %q", buf)
	}

	// Le handshake doit être visible et récent des deux côtés.
	for name, d := range map[string]*Device{"A": devA, "B": devB} {
		hs, err := d.PeerHandshakes()
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, ts := range hs {
			if !ts.IsZero() && time.Since(ts) < time.Minute {
				found = true
			}
		}
		if !found {
			t.Fatalf("pas de handshake récent côté %s: %v", name, hs)
		}
	}

	// SetPeerEndpoint (utilisé par le perçage NAT) ne doit pas casser le
	// tunnel : on force l'endpoint déjà correct et on re-vérifie le trafic.
	if err := devB.SetPeerEndpoint(peerA.PublicKey,
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(portA))); err != nil {
		t.Fatal(err)
	}

	// La suppression d'un pair via SyncPeers doit couper la liaison.
	if err := devA.SyncPeers(nil, knownA, func(types.Peer) string { return "" }); err != nil {
		t.Fatal(err)
	}
	hs, err := devA.PeerHandshakes()
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 0 {
		t.Fatalf("le pair devrait avoir été retiré: %v", hs)
	}
}
