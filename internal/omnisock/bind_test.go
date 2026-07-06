package omnisock

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/stun"
)

// openBind ouvre un Bind sur un port éphémère et démarre sa boucle de
// réception comme le ferait wireguard-go, en collectant les paquets WG.
func openBind(t *testing.T) (*Bind, netip.AddrPort, chan []byte) {
	t.Helper()
	b := New()
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	wgPackets := make(chan []byte, 16)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		eps := make([]conn.Endpoint, 1)
		for {
			n, err := fns[0](bufs, sizes, eps)
			if err != nil {
				return
			}
			if n == 1 {
				pkt := make([]byte, sizes[0])
				copy(pkt, bufs[0][:sizes[0]])
				wgPackets <- pkt
			}
		}
	}()
	return b, netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(int(port))), wgPackets
}

func TestDiscoPingPong(t *testing.T) {
	a, _, _ := openBind(t)
	b, bAddr, _ := openBind(t)
	_ = b

	var mu sync.Mutex
	var got []netip.AddrPort
	pongs := make(chan struct{}, 1)
	a.SetPongHandler(func(id DiscoTxID, from netip.AddrPort) {
		mu.Lock()
		got = append(got, from)
		mu.Unlock()
		pongs <- struct{}{}
	})

	if _, err := a.SendPing(bAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pongs:
	case <-time.After(2 * time.Second):
		t.Fatal("pas de pong reçu : b devrait répondre automatiquement aux pings")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Port() != bAddr.Port() {
		t.Fatalf("pong depuis %v, attendu port %d", got, bAddr.Port())
	}
}

func TestSTUNThroughBind(t *testing.T) {
	// Serveur STUN réel sur loopback.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go stun.Serve(ctx, pc)

	b, _, _ := openBind(t)
	mapped, err := b.STUNRequest(context.Background(), pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if int(mapped.Port()) != b.LocalPort() {
		t.Fatalf("le STUN devrait découvrir notre port %d, obtenu %d", b.LocalPort(), mapped.Port())
	}
}

func TestWGPacketsPassThrough(t *testing.T) {
	a, _, _ := openBind(t)
	_, bAddr, bPackets := openBind(t)

	// Un paquet WireGuard (type 4, données de transport) doit être remis
	// au moteur, pas intercepté.
	wgPkt := make([]byte, 32)
	wgPkt[0] = 0x04
	ep, err := a.ParseEndpoint(bAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send([][]byte{wgPkt}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-bPackets:
		if pkt[0] != 0x04 || len(pkt) != 32 {
			t.Fatalf("paquet altéré: %v", pkt[:5])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("le paquet WireGuard n'a pas été remis au moteur")
	}
}

func TestClassification(t *testing.T) {
	if !isDisco(encodeDisco(discoPing, NewDiscoTxID())) {
		t.Fatal("un ping disco doit être classé disco")
	}
	wgHandshake := make([]byte, 148)
	wgHandshake[0] = 0x01
	if isDisco(wgHandshake) || stun.IsBindingResponse(wgHandshake) {
		t.Fatal("un handshake WireGuard ne doit être ni disco ni STUN")
	}
	resp := stun.BuildBindingResponse(stun.NewTxID(), netip.MustParseAddrPort("1.2.3.4:5"))
	if !stun.IsBindingResponse(resp) || isDisco(resp) {
		t.Fatal("une réponse STUN doit être classée STUN uniquement")
	}
}
