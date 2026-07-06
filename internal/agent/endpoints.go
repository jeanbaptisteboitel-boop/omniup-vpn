package agent

import (
	"context"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/relay"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

// handshakeFresh : au-delà, on considère le chemin vers le pair mort et on
// relance le perçage (WireGuard renégocie toutes les ~120 s).
const handshakeFresh = 135 * time.Second

// EndpointManager choisit le meilleur endpoint pour chaque pair :
// il sonde tous les candidats (adresses LAN, endpoint public STUN,
// endpoint observé par le serveur) avec des pings disco, et applique le
// premier chemin qui répond. L'envoi des sondes ouvre au passage notre
// mapping NAT vers chaque candidat — les deux pairs le faisant
// simultanément, c'est le perçage UDP.
// relayAfterRounds : nombre de cycles sans handshake avant de basculer un
// pair sur le relais de secours (les sondes directes continuent ensuite,
// et le premier pong ramène le pair en direct).
const relayAfterRounds = 2

type EndpointManager struct {
	dev  *wgnet.Device
	bind *omnisock.Bind

	mu           sync.Mutex
	pending      map[omnisock.DiscoTxID]pendingProbe
	peers        map[string][]string // clé publique -> candidats connus
	relayOK      bool
	disconnected map[string]int  // cycles consécutifs sans handshake
	onRelay      map[string]bool // pairs actuellement joints via le relais
}

type pendingProbe struct {
	publicKey string
	candidate netip.AddrPort
	sentAt    time.Time
}

func NewEndpointManager(dev *wgnet.Device, bind *omnisock.Bind) *EndpointManager {
	m := &EndpointManager{
		dev:          dev,
		bind:         bind,
		pending:      map[omnisock.DiscoTxID]pendingProbe{},
		peers:        map[string][]string{},
		disconnected: map[string]int{},
		onRelay:      map[string]bool{},
	}
	bind.SetPongHandler(m.onPong)
	return m
}

// SetRelayAvailable signale si le relais de secours répond actuellement.
func (m *EndpointManager) SetRelayAvailable(ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relayOK = ok
}

// Observe met à jour les candidats connus depuis la carte du réseau.
func (m *EndpointManager) Observe(peers []types.Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = map[string][]string{}
	for _, p := range peers {
		m.peers[p.PublicKey] = candidatesOf(p)
	}
	// Oubli des pairs retirés de la carte.
	for pub := range m.disconnected {
		if _, ok := m.peers[pub]; !ok {
			delete(m.disconnected, pub)
		}
	}
	for pub := range m.onRelay {
		if _, ok := m.peers[pub]; !ok {
			delete(m.onRelay, pub)
		}
	}
}

// Probe envoie une salve de sondes vers tous les candidats des pairs sans
// handshake récent. Appelée à chaque cycle de synchronisation.
func (m *EndpointManager) Probe() {
	handshakes, err := m.dev.PeerHandshakes()
	if err != nil {
		log.Printf("perçage: lecture des handshakes: %v", err)
		return
	}

	m.mu.Lock()
	// Purge des sondes expirées.
	for id, pr := range m.pending {
		if time.Since(pr.sentAt) > 15*time.Second {
			delete(m.pending, id)
		}
	}
	type probe struct {
		pub string
		ap  netip.AddrPort
	}
	var toSend []probe
	var toRelay []string
	for pub, candidates := range m.peers {
		fresh := false
		if hs, ok := handshakes[pub]; ok && time.Since(hs) < handshakeFresh {
			fresh = true
		}
		if fresh && !m.onRelay[pub] {
			m.disconnected[pub] = 0
			continue // chemin direct actif : ne pas perturber
		}
		if !fresh {
			m.disconnected[pub]++
			// Le perçage n'aboutit pas : bascule sur le relais de secours.
			if m.relayOK && !m.onRelay[pub] && m.disconnected[pub] > relayAfterRounds {
				toRelay = append(toRelay, pub)
				m.onRelay[pub] = true
			}
		}
		// Même via le relais, on continue de sonder les chemins directs :
		// le premier pong ramènera le pair en direct.
		for _, c := range candidates {
			if ap, err := netip.ParseAddrPort(c); err == nil {
				toSend = append(toSend, probe{pub, ap})
			}
		}
	}
	m.mu.Unlock()

	for _, pub := range toRelay {
		if err := m.dev.SetPeerEndpointString(pub, relay.EndpointString(pub)); err != nil {
			log.Printf("relais: bascule de %s: %v", shortKey(pub), err)
			m.mu.Lock()
			delete(m.onRelay, pub)
			m.mu.Unlock()
			continue
		}
		log.Printf("pair %s injoignable en direct : bascule sur le relais", shortKey(pub))
	}

	for _, p := range toSend {
		id, err := m.bind.SendPing(p.ap)
		if err != nil {
			continue
		}
		m.mu.Lock()
		m.pending[id] = pendingProbe{publicKey: p.pub, candidate: p.ap, sentAt: time.Now()}
		m.mu.Unlock()
	}
}

// onPong applique le premier chemin direct confirmé : pour un pair
// déconnecté, ou pour un pair actuellement relayé (retour au direct).
func (m *EndpointManager) onPong(id omnisock.DiscoTxID, from netip.AddrPort) {
	m.mu.Lock()
	pr, ok := m.pending[id]
	if ok {
		delete(m.pending, id)
	}
	viaRelay := ok && m.onRelay[pr.publicKey]
	m.mu.Unlock()
	if !ok {
		return
	}

	if !viaRelay {
		handshakes, err := m.dev.PeerHandshakes()
		if err == nil {
			if hs, ok := handshakes[pr.publicKey]; ok && time.Since(hs) < handshakeFresh {
				return // déjà connecté en direct : ne pas déstabiliser
			}
		}
	}
	// Le pong peut revenir d'une adresse différente du candidat sondé
	// (NAT) : « from » est la vérité.
	if err := m.dev.SetPeerEndpoint(pr.publicKey, from); err != nil {
		log.Printf("perçage: endpoint %s: %v", from, err)
		return
	}
	m.mu.Lock()
	delete(m.onRelay, pr.publicKey)
	m.disconnected[pr.publicKey] = 0
	m.mu.Unlock()
	if viaRelay {
		log.Printf("chemin direct retrouvé vers %s via %s (sortie du relais)", shortKey(pr.publicKey), from)
	} else {
		log.Printf("perçage réussi vers %s via %s", shortKey(pr.publicKey), from)
	}
}

// candidatesOf ordonne les candidats d'un pair : endpoints rapportés par
// l'agent distant (public STUN puis LAN), puis endpoint observé par le
// serveur de coordination.
func candidatesOf(p types.Peer) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ep string) {
		if ep != "" && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	for _, ep := range p.Endpoints {
		add(ep)
	}
	add(p.Endpoint)
	return out
}

// InitialEndpoint donne l'endpoint de départ d'un pair nouvellement ajouté
// (le perçage affinera ensuite).
func InitialEndpoint(p types.Peer) string {
	if c := candidatesOf(p); len(c) > 0 {
		return c[0]
	}
	return ""
}

// DiscoverEndpoints construit la liste ordonnée de nos propres candidats :
// endpoint public découvert par STUN d'abord, puis adresses locales.
func DiscoverEndpoints(ctx context.Context, bind *omnisock.Bind, stunServers []string, skipIface string) []string {
	port := bind.LocalPort()
	if port == 0 {
		return nil
	}
	var out []string
	for _, srv := range stunServers {
		if mapped, err := bind.STUNRequest(ctx, srv); err == nil {
			out = append(out, mapped.String())
			break
		}
	}
	for _, ip := range localIPv4(skipIface) {
		out = append(out, net.JoinHostPort(ip, strconv.Itoa(port)))
	}
	return dedup(out)
}

// localIPv4 liste les adresses IPv4 locales utilisables comme candidats
// (hors loopback, hors interface overlay, hors plage du VPN).
func localIPv4(skipIface string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == skipIface {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || !ip.IsGlobalUnicast() || inOverlay(ip) {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// inOverlay reconnaît la plage CGNAT du VPN (100.64.0.0/10).
func inOverlay(ip net.IP) bool {
	return ip[0] == 100 && ip[1] >= 64 && ip[1] < 128
}

// DefaultSTUNServer déduit le serveur STUN du serveur de coordination
// (même hôte, port 3478).
func DefaultSTUNServer(serverURL string) string {
	return hostWithPort(serverURL, "3478")
}

// DefaultRelayServer déduit le relais de secours du serveur de
// coordination (même hôte, port 3479).
func DefaultRelayServer(serverURL string) string {
	return hostWithPort(serverURL, "3479")
}

func hostWithPort(serverURL, port string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func shortKey(pub string) string {
	if len(pub) > 12 {
		return pub[:12] + "…"
	}
	return pub
}
