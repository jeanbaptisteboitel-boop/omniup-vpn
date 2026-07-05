package wgnet

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/relay"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// TestTunnelViaRelay fait dialoguer deux moteurs WireGuard qui ne
// connaissent AUCUN endpoint direct l'un de l'autre : tout le trafic
// transite par le relais (le cas NAT symétrique des deux côtés).
func TestTunnelViaRelay(t *testing.T) {
	// Relais réel sur loopback.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.Serve(ctx, pc)
	relayAP := netip.MustParseAddrPort(pc.LocalAddr().String())

	privA, _ := wgtypes.GeneratePrivateKey()
	privB, _ := wgtypes.GeneratePrivateKey()
	ipA := netip.MustParseAddr("100.98.0.1")
	ipB := netip.MustParseAddr("100.98.0.2")

	startNode := func(name string, priv wgtypes.Key, ip netip.Addr) (*Device, *netstack.Net) {
		tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{ip}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		bind := omnisock.New()
		if err := bind.ConfigureRelay(relayAP, [32]byte(priv)); err != nil {
			t.Fatal(err)
		}
		dev, err := StartWithTUN(tunDev, name, priv, 0, bind, false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(dev.Close)
		if err := bind.RelayRegister(); err != nil {
			t.Fatal(err)
		}
		return dev, tnet
	}

	devA, tnetA := startNode("relay-a", privA, ipA)
	devB, tnetB := startNode("relay-b", privB, ipB)

	// L'ACK du relais doit revenir sur chaque socket.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !(devA.Bind.RelayHealthy() && devB.Bind.RelayHealthy()) {
		time.Sleep(50 * time.Millisecond)
	}
	if !devA.Bind.RelayHealthy() || !devB.Bind.RelayHealthy() {
		t.Fatal("les deux sockets devraient avoir reçu l'ACK du relais")
	}

	// Chaque pair est configuré avec un endpoint RELAIS uniquement —
	// aucune adresse directe n'est jamais échangée.
	pubA, pubB := privA.PublicKey().String(), privB.PublicKey().String()
	if err := devA.SyncPeers([]types.Peer{{PublicKey: pubB, IP: ipB.String()}},
		map[string]bool{}, func(types.Peer) string { return relay.EndpointString(pubB) }); err != nil {
		t.Fatal(err)
	}
	if err := devB.SyncPeers([]types.Peer{{PublicKey: pubA, IP: ipA.String()}},
		map[string]bool{}, func(types.Peer) string { return relay.EndpointString(pubA) }); err != nil {
		t.Fatal(err)
	}

	// Écho TCP à travers le tunnel relayé.
	ln, err := tnetB.ListenTCP(&net.TCPAddr{Port: 7778})
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

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer dialCancel()
	conn, err := tnetA.DialContext(dialCtx, "tcp", ipB.String()+":7778")
	if err != nil {
		t.Fatalf("connexion à travers le tunnel relayé: %v", err)
	}
	defer conn.Close()

	msg := "bonjour via le relais"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("lecture de l'écho relayé: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("écho corrompu: %q", buf)
	}

	// Le handshake a bien eu lieu à travers le relais.
	hs, err := devA.PeerHandshakes()
	if err != nil {
		t.Fatal(err)
	}
	if ts, ok := hs[pubB]; !ok || ts.IsZero() {
		t.Fatal("pas de handshake via le relais côté A")
	}
}
