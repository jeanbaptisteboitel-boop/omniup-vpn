// Package dnssrv implémente le DNS interne du réseau (équivalent MagicDNS) :
// chaque machine résout <nom>.<zone> vers l'adresse overlay du pair,
// à partir de la carte du réseau distribuée par le serveur de coordination.
package dnssrv

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// TTL des réponses : courte, car la carte du réseau évolue.
const recordTTL = 30

// Server répond aux requêtes A pour la zone interne du VPN.
type Server struct {
	zone string // fqdn, ex: "omni."

	mu      sync.RWMutex
	records map[string]net.IP // fqdn (minuscules) -> IP overlay
}

// New crée un serveur DNS pour la zone donnée (ex: "omni").
func New(zone string) *Server {
	zone = strings.Trim(strings.ToLower(zone), ".") + "."
	return &Server{zone: zone, records: map[string]net.IP{}}
}

// Zone renvoie la zone servie, avec point final (ex: "omni.").
func (s *Server) Zone() string { return s.zone }

// Update reconstruit la table des noms à partir de la carte du réseau
// (le nom de la machine locale est inclus).
func (s *Server) Update(nm *types.NetMap) {
	records := make(map[string]net.IP, len(nm.Peers)+1)
	add := func(p types.Peer) {
		label := sanitizeLabel(p.Hostname)
		ip := net.ParseIP(p.IP)
		if label == "" || ip == nil {
			return
		}
		records[label+"."+s.zone] = ip
	}
	add(nm.Self)
	for _, p := range nm.Peers {
		add(p)
	}

	s.mu.Lock()
	s.records = records
	s.mu.Unlock()
}

// ServeDNS implémente dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	// Hors de notre zone : refus (le résolveur du système doit être
	// configuré pour ne nous envoyer que la zone interne).
	if !strings.HasSuffix(name, "."+s.zone) && name != s.zone {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	s.mu.RLock()
	ip, ok := s.records[name]
	s.mu.RUnlock()

	if !ok {
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		_ = w.WriteMsg(m)
		return
	}
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: recordTTL},
			A:   ip.To4(),
		})
	}
	// Nom connu mais type non géré (AAAA…) : réponse vide NOERROR.
	_ = w.WriteMsg(m)
}

// ListenAndServe écoute en UDP sur addr jusqu'à annulation du contexte.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	srv := &dns.Server{PacketConn: pc, Handler: s}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown()
	}()
	return srv.ActivateAndServe()
}

// sanitizeLabel convertit un nom de machine en label DNS valide :
// minuscules, caractères hors [a-z0-9-] remplacés par des tirets.
func sanitizeLabel(hostname string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(hostname) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == '.', r == '_', r == ' ':
			b.WriteRune('-')
		}
	}
	label := strings.Trim(b.String(), "-")
	if len(label) > 63 {
		label = label[:63]
	}
	return label
}
