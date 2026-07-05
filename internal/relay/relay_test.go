package relay

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
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

func TestProofVerification(t *testing.T) {
	var relayPriv, clientPriv [32]byte
	rand.Read(relayPriv[:])
	rand.Read(clientPriv[:])
	relayPubS, _ := curve25519.X25519(relayPriv[:], curve25519.Basepoint)
	var relayPub [32]byte
	copy(relayPub[:], relayPubS)

	var nonce [nonceLen]byte
	rand.Read(nonce[:])

	proof, err := BuildProof(clientPriv, relayPub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, gotNonce, mac, ok := ParseProof(proof)
	if !ok || gotNonce != nonce {
		t.Fatal("décodage PROOF incorrect")
	}
	if !VerifyProof(relayPriv, clientPub, nonce, mac) {
		t.Fatal("une preuve légitime devrait être acceptée")
	}

	// Un usurpateur revendiquant la clé publique d'autrui sans détenir la
	// clé privée ne peut pas produire un MAC valide.
	var otherPub [32]byte
	rand.Read(otherPub[:])
	if VerifyProof(relayPriv, otherPub, nonce, mac) {
		t.Fatal("une preuve pour une autre clé devrait être refusée")
	}
	// Nonce différent : rejeu refusé.
	var otherNonce [nonceLen]byte
	rand.Read(otherNonce[:])
	if VerifyProof(relayPriv, clientPub, otherNonce, mac) {
		t.Fatal("une preuve rejouée avec un autre nonce devrait être refusée")
	}
}

// testClient : socket UDP + paire de clés Curve25519 réelle.
type testClient struct {
	conn *net.UDPConn
	priv [32]byte
	key  [32]byte // clé publique
}

func newTestClient(t *testing.T, relayAddr string) *testClient {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, mustUDP(t, relayAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &testClient{conn: conn}
	if _, err := rand.Read(c.priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(c.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.key[:], pub)
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

func (c *testClient) read(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, maxPacket)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.conn.Read(buf)
	if err != nil {
		t.Fatalf("lecture: %v", err)
	}
	return buf[:n]
}

// register déroule le défi-réponse complet et attend l'ACK.
func (c *testClient) register(t *testing.T) {
	t.Helper()
	if _, err := c.conn.Write(BuildRegister(c.key)); err != nil {
		t.Fatal(err)
	}
	resp := c.read(t)
	if !IsFrame(resp) || FrameType(resp) != TypeChallenge {
		t.Fatalf("attendu CHALLENGE, reçu type %d", FrameType(resp))
	}
	relayPub, nonce, ok := ParseChallenge(resp)
	if !ok {
		t.Fatal("CHALLENGE indécodable")
	}
	proof, err := BuildProof(c.priv, relayPub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.conn.Write(proof); err != nil {
		t.Fatal(err)
	}
	resp = c.read(t)
	if !IsFrame(resp) || FrameType(resp) != TypeAck {
		t.Fatalf("attendu ACK après la preuve, reçu type %d", FrameType(resp))
	}
}

func startRelay(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, pc)
	return pc.LocalAddr().String()
}

func TestServerForwards(t *testing.T) {
	addr := startRelay(t)
	a := newTestClient(t, addr)
	b := newTestClient(t, addr)
	a.register(t)
	b.register(t)

	// Ré-enregistrement (keepalive) : ACK direct, sans nouveau défi.
	if _, err := a.conn.Write(BuildRegister(a.key)); err != nil {
		t.Fatal(err)
	}
	if resp := a.read(t); FrameType(resp) != TypeAck {
		t.Fatalf("le keepalive devrait recevoir un ACK direct, reçu type %d", FrameType(resp))
	}

	// a envoie à b via le relais.
	payload := []byte("bonjour b")
	if _, err := a.conn.Write(BuildForward(b.key, payload)); err != nil {
		t.Fatal(err)
	}
	resp := b.read(t)
	if FrameType(resp) != TypeRecv {
		t.Fatalf("b devrait recevoir une trame RECV: %v", resp[:6])
	}
	srcKey, gotPayload, ok := ParseKeyed(resp)
	if !ok || srcKey != a.key || string(gotPayload) != string(payload) {
		t.Fatalf("trame RECV incorrecte: src=%x payload=%q", srcKey[:4], gotPayload)
	}
}

func TestServerDropsUnauthenticated(t *testing.T) {
	addr := startRelay(t)
	b := newTestClient(t, addr)
	b.register(t)

	// Expéditeur jamais authentifié : la trame doit être ignorée.
	stranger := newTestClient(t, addr)
	if _, err := stranger.conn.Write(BuildForward(b.key, []byte("intrusion"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxPacket)
	b.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := b.conn.Read(buf); err == nil {
		t.Fatalf("b ne devrait rien recevoir d'un inconnu, reçu %d octets", n)
	}
}

func TestServerRejectsBadProof(t *testing.T) {
	addr := startRelay(t)
	c := newTestClient(t, addr)

	if _, err := c.conn.Write(BuildRegister(c.key)); err != nil {
		t.Fatal(err)
	}
	resp := c.read(t)
	relayPub, nonce, ok := ParseChallenge(resp)
	if !ok {
		t.Fatal("CHALLENGE attendu")
	}
	// Preuve construite avec une MAUVAISE clé privée : pas d'ACK.
	var wrongPriv [32]byte
	rand.Read(wrongPriv[:])
	proof, err := BuildProof(wrongPriv, relayPub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	// On force la clé revendiquée à celle de c (usurpation).
	copy(proof[headerLen:headerLen+keyLen], c.key[:])
	if _, err := c.conn.Write(proof); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxPacket)
	c.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.conn.Read(buf); err == nil {
		t.Fatal("une preuve forgée ne devrait pas recevoir d'ACK")
	}
}
