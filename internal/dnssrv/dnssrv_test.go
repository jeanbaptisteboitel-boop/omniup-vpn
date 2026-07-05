package dnssrv

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := New("omni")
	s.Update(&types.NetMap{
		Self: types.Peer{Hostname: "Alpha Machine", IP: "100.64.0.1"},
		Peers: []types.Peer{
			{Hostname: "beta", IP: "100.64.0.2"},
			{Hostname: "", IP: "100.64.0.3"}, // sans nom : ignorée
		},
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: s}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return s, pc.LocalAddr().String()
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := &dns.Client{Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestResolvePeers(t *testing.T) {
	_, addr := startServer(t)

	resp := query(t, addr, "beta.omni.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("réponse inattendue pour beta.omni: %v", resp)
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "100.64.0.2" {
		t.Fatalf("beta.omni devrait résoudre 100.64.0.2, obtenu %s", a.A)
	}

	// Le nom local est nettoyé : « Alpha Machine » → alpha-machine.
	resp = query(t, addr, "alpha-machine.omni.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("le nom de la machine locale devrait résoudre: %v", resp)
	}

	// Insensible à la casse.
	resp = query(t, addr, "BETA.omni.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("la résolution devrait être insensible à la casse: %v", resp)
	}
}

func TestUnknownAndOutOfZone(t *testing.T) {
	_, addr := startServer(t)

	if resp := query(t, addr, "inconnu.omni.", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("nom inconnu : NXDOMAIN attendu, obtenu %d", resp.Rcode)
	}
	if resp := query(t, addr, "example.com.", dns.TypeA); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("hors zone : REFUSED attendu, obtenu %d", resp.Rcode)
	}
	// Nom connu, type non géré : NOERROR sans réponse.
	if resp := query(t, addr, "beta.omni.", dns.TypeAAAA); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("AAAA : NOERROR vide attendu, obtenu %v", resp)
	}
}

func TestUpdateReplacesRecords(t *testing.T) {
	s, addr := startServer(t)
	s.Update(&types.NetMap{
		Self:  types.Peer{Hostname: "alpha-machine", IP: "100.64.0.1"},
		Peers: []types.Peer{{Hostname: "delta", IP: "100.64.0.9"}},
	})

	if resp := query(t, addr, "delta.omni.", dns.TypeA); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("delta devrait résoudre après mise à jour: %d", resp.Rcode)
	}
	if resp := query(t, addr, "beta.omni.", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("beta devrait avoir disparu après mise à jour: %d", resp.Rcode)
	}
}

func TestListenAndServeStopsOnCancel(t *testing.T) {
	s := New("omni")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx, "127.0.0.1:0") }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("le serveur DNS ne s'arrête pas à l'annulation du contexte")
	}
}
