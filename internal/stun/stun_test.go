package stun

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTripEncoding(t *testing.T) {
	id := NewTxID()
	req := BuildBindingRequest(id)
	if !IsMessage(req) {
		t.Fatal("la requête devrait être reconnue comme message STUN")
	}
	gotID, err := ParseBindingRequest(req)
	if err != nil || gotID != id {
		t.Fatalf("txid non retrouvé: %v", err)
	}

	addr := netip.MustParseAddrPort("203.0.113.7:41641")
	resp := BuildBindingResponse(id, addr)
	if !IsBindingResponse(resp) {
		t.Fatal("la réponse devrait être reconnue comme Binding response")
	}
	respID, mapped, err := ParseBindingResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if respID != id || mapped != addr {
		t.Fatalf("attendu %s, obtenu %s", addr, mapped)
	}
}

func TestIPv6Response(t *testing.T) {
	id := NewTxID()
	addr := netip.MustParseAddrPort("[2001:db8::1]:5000")
	_, mapped, err := ParseBindingResponse(BuildBindingResponse(id, addr))
	if err != nil || mapped != addr {
		t.Fatalf("ipv6: attendu %s, obtenu %s (%v)", addr, mapped, err)
	}
}

func TestNotSTUN(t *testing.T) {
	// Un paquet WireGuard (handshake initiation) ne doit pas passer pour
	// du STUN : octet 0 = 0x01 mais pas de magic cookie.
	wg := make([]byte, 148)
	wg[0] = 0x01
	if IsMessage(wg) {
		t.Fatal("un paquet WireGuard ne doit pas être classé STUN")
	}
	if IsMessage([]byte{0x00, 0x01}) {
		t.Fatal("paquet trop court accepté")
	}
}

func TestServeOverUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, pc) }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	id := NewTxID()
	if _, err := client.Write(BuildBindingRequest(id)); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	respID, mapped, err := ParseBindingResponse(buf[:n])
	if err != nil || respID != id {
		t.Fatalf("réponse invalide: %v", err)
	}
	local := client.LocalAddr().(*net.UDPAddr)
	if int(mapped.Port()) != local.Port {
		t.Fatalf("le serveur devrait renvoyer notre port source %d, obtenu %d", local.Port, mapped.Port())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("le serveur STUN ne s'arrête pas")
	}
}
