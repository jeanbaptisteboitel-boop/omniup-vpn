package relay

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFrameCodec(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	payload := []byte("paquet wireguard chiffré")

	fwd := BuildForward(key, payload)
	if !IsFrame(fwd) || FrameType(fwd) != TypeForward {
		t.Fatal("trame FORWARD mal encodée")
	}
	gotKey, gotPayload, ok := ParseKeyed(fwd)
	if !ok || gotKey != key || string(gotPayload) != string(payload) {
		t.Fatal("décodage FORWARD incorrect")
	}

	reg := BuildRegister(key)
	if FrameType(reg) != TypeRegister {
		t.Fatal("trame REGISTER mal encodée")
	}
	if !IsFrame(BuildAck()) || FrameType(BuildAck()) != TypeAck {
		t.Fatal("trame ACK mal encodée")
	}

	// Un paquet WireGuard ne doit pas passer pour une trame relais.
	wg := make([]byte, 148)
	wg[0] = 0x01
	if IsFrame(wg) {
		t.Fatal("un paquet WireGuard ne doit pas être classé relais")
	}
}

func TestKeyB64RoundTrip(t *testing.T) {
	var key [32]byte
	key[0], key[31] = 0xAB, 0xCD
	got, ok := KeyFromB64(KeyToB64(key))
	if !ok || got != key {
		t.Fatal("aller-retour base64 incorrect")
	}
	if _, ok := KeyFromB64("pas-du-base64!!"); ok {
		t.Fatal("clé invalide acceptée")
	}
	if ep := EndpointString(KeyToB64(key)); ep[:6] != "relay:" {
		t.Fatalf("endpoint relais inattendu: %s", ep)
	}
}

// client de test : socket UDP + clé.
type testClient struct {
	conn *net.UDPConn
	key  [32]byte
}

func newTestClient(t *testing.T, relayAddr string, keySeed byte) *testClient {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, mustUDP(t, relayAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &testClient{conn: conn}
	for i := range c.key {
		c.key[i] = keySeed
	}
	return c
}

func mustUDP(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (c *testClient) register(t *testing.T) {
	t.Helper()
	if _, err := c.conn.Write(BuildRegister(c.key)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxPacket)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.conn.Read(buf)
	if err != nil {
		t.Fatalf("pas d'ACK du relais: %v", err)
	}
	if !IsFrame(buf[:n]) || FrameType(buf[:n]) != TypeAck {
		t.Fatalf("réponse inattendue au REGISTER: %v", buf[:n])
	}
}

func TestServerForwards(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, pc)

	a := newTestClient(t, pc.LocalAddr().String(), 0xAA)
	b := newTestClient(t, pc.LocalAddr().String(), 0xBB)
	a.register(t)
	b.register(t)

	// a envoie à b via le relais.
	payload := []byte("bonjour b")
	if _, err := a.conn.Write(BuildForward(b.key, payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxPacket)
	b.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := b.conn.Read(buf)
	if err != nil {
		t.Fatalf("b n'a rien reçu: %v", err)
	}
	if FrameType(buf[:n]) != TypeRecv {
		t.Fatalf("b devrait recevoir une trame RECV: %v", buf[:6])
	}
	srcKey, gotPayload, ok := ParseKeyed(buf[:n])
	if !ok || srcKey != a.key || string(gotPayload) != string(payload) {
		t.Fatalf("trame RECV incorrecte: src=%x payload=%q", srcKey[:4], gotPayload)
	}
}

func TestServerDropsUnregisteredSender(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, pc)

	b := newTestClient(t, pc.LocalAddr().String(), 0xBB)
	b.register(t)

	// Expéditeur jamais enregistré : la trame doit être ignorée.
	stranger := newTestClient(t, pc.LocalAddr().String(), 0xEE)
	if _, err := stranger.conn.Write(BuildForward(b.key, []byte("intrusion"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxPacket)
	b.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := b.conn.Read(buf); err == nil {
		t.Fatalf("b ne devrait rien recevoir d'un inconnu, reçu %d octets", n)
	}
}
