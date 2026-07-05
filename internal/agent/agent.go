// Package agent implémente la logique du démon omnid : enregistrement
// auprès du serveur de coordination, moteur WireGuard userspace avec
// socket magique (STUN + perçage NAT), et synchronisation périodique
// des pairs.
package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/dnssrv"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

// PollInterval : fréquence de synchronisation avec le serveur de coordination.
const PollInterval = 10 * time.Second

// stunRefresh : fréquence de redécouverte de notre endpoint public.
const stunRefresh = 25 * time.Second

// Options configure le démarrage de l'agent.
type Options struct {
	ServerURL   string
	AuthKey     string
	Hostname    string
	Iface       string
	ListenPort  int
	MTU         int
	StatePath   string
	STUNServers []string // vide : déduit du serveur de coordination
	RelayServer string   // vide : déduit du serveur de coordination ; "off" : désactivé
	DNS         bool     // activer le DNS interne sur l'adresse overlay
	DNSZone     string   // zone interne, ex: "omni"
}

// Up enregistre la machine si nécessaire, démarre le moteur WireGuard
// userspace et boucle jusqu'à annulation du contexte : synchronisation des
// pairs, découverte STUN et perçage NAT.
func Up(ctx context.Context, opts Options) error {
	st, err := LoadState(opts.StatePath)
	if err != nil {
		return fmt.Errorf("lecture de l'état: %w", err)
	}

	if st == nil {
		if opts.AuthKey == "" {
			return fmt.Errorf("première connexion : --auth-key est requis")
		}
		if opts.ServerURL == "" {
			return fmt.Errorf("première connexion : --server est requis")
		}
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		c := NewClient(opts.ServerURL, "")
		reg, err := c.Register(opts.AuthKey, opts.Hostname, priv.PublicKey().String())
		if err != nil {
			return fmt.Errorf("enregistrement: %w", err)
		}
		st = &State{
			ServerURL:   c.ServerURL,
			PrivateKey:  priv.String(),
			DeviceID:    reg.DeviceID,
			DeviceToken: reg.DeviceToken,
			IP:          reg.IP,
			CIDR:        reg.CIDR,
			Iface:       opts.Iface,
			ListenPort:  opts.ListenPort,
		}
		if err := st.Save(opts.StatePath); err != nil {
			return fmt.Errorf("sauvegarde de l'état: %w", err)
		}
		log.Printf("machine enregistrée, adresse attribuée: %s", st.IP)
	} else {
		log.Printf("identité existante chargée: %s (%s)", st.IP, st.Iface)
	}

	priv, err := wgtypes.ParseKey(st.PrivateKey)
	if err != nil {
		return fmt.Errorf("clé privée corrompue dans l'état: %w", err)
	}

	mtu := opts.MTU
	if mtu == 0 {
		mtu = wgnet.DefaultMTU
	}
	bind := omnisock.New()
	dev, err := wgnet.Start(st.Iface, mtu, priv, st.ListenPort, bind)
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := dev.SetAddress(st.IP, st.CIDR); err != nil {
		return err
	}
	log.Printf("interface %s active (%s), moteur WireGuard userspace, port %d",
		dev.Name, st.IP, bind.LocalPort())

	writePidFile(opts.StatePath)
	defer removePidFile(opts.StatePath)

	stunServers := opts.STUNServers
	if len(stunServers) == 0 {
		if srv := DefaultSTUNServer(st.ServerURL); srv != "" {
			stunServers = []string{srv}
		}
	}

	// Relais de secours : configuré sur la socket, utilisé par le
	// gestionnaire d'endpoints quand le perçage direct échoue.
	relayServer := opts.RelayServer
	if relayServer == "" {
		relayServer = DefaultRelayServer(st.ServerURL)
	}
	relayEnabled := false
	if relayServer != "" && relayServer != "off" {
		if udpAddr, err := net.ResolveUDPAddr("udp4", relayServer); err == nil {
			ap := udpAddr.AddrPort()
			bind.ConfigureRelay(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), [32]byte(priv.PublicKey()))
			relayEnabled = true
			log.Printf("relais de secours: %s", relayServer)
		} else {
			log.Printf("relais de secours indisponible (%v)", err)
		}
	}

	// DNS interne : résout <machine>.<zone> vers les adresses overlay.
	var dnsSrv *dnssrv.Server
	if opts.DNS {
		dnsSrv = dnssrv.New(opts.DNSZone)
		addr := net.JoinHostPort(st.IP, "53")
		go func() {
			if err := dnsSrv.ListenAndServe(ctx, addr); err != nil && ctx.Err() == nil {
				log.Printf("dns interne désactivé (%v)", err)
			}
		}()
		log.Printf("dns interne sur %s (zone %s)", addr, dnsSrv.Zone())
	}

	mgr := NewEndpointManager(dev, bind)
	client := NewClient(st.ServerURL, st.DeviceToken)
	knownPeers := map[string]bool{}
	var myEndpoints []string
	var lastSTUN time.Time

	sync := func() {
		// 0. Maintien de l'enregistrement auprès du relais de secours.
		if relayEnabled {
			if err := bind.RelayRegister(); err != nil {
				log.Printf("relais: %v", err)
			}
			mgr.SetRelayAvailable(bind.RelayHealthy())
		}

		// 1. Redécouverte périodique de notre endpoint public (STUN).
		if time.Since(lastSTUN) > stunRefresh {
			if eps := DiscoverEndpoints(ctx, bind, stunServers, dev.Name); len(eps) > 0 {
				if len(eps) > 0 && (len(myEndpoints) == 0 || eps[0] != myEndpoints[0]) {
					log.Printf("endpoints locaux: %v", eps)
				}
				myEndpoints = eps
			}
			lastSTUN = time.Now()
		}

		// 2. Heartbeat + carte du réseau.
		nm, err := client.Poll(types.PollRequest{ListenPort: st.ListenPort, Endpoints: myEndpoints})
		if err != nil {
			log.Printf("poll: %v", err)
			return
		}

		// 3. Synchronisation des pairs (sans toucher aux endpoints établis).
		if err := dev.SyncPeers(nm.Peers, knownPeers, InitialEndpoint); err != nil {
			log.Printf("synchronisation wireguard: %v", err)
			return
		}

		// 4. Perçage NAT pour les pairs sans chemin actif.
		mgr.Observe(nm.Peers)
		mgr.Probe()

		if dnsSrv != nil {
			dnsSrv.Update(nm)
		}
		logNetMapChange(nm)
	}

	sync()
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("arrêt de l'agent — l'interface %s disparaît avec le démon", dev.Name)
			return nil
		case <-ticker.C:
			sync()
		}
	}
}

var lastPeerCount = -1

func logNetMapChange(nm *types.NetMap) {
	online := 0
	for _, p := range nm.Peers {
		if p.Online {
			online++
		}
	}
	if len(nm.Peers) != lastPeerCount {
		log.Printf("carte du réseau: %d pair(s), %d en ligne", len(nm.Peers), online)
		lastPeerCount = len(nm.Peers)
	}
}

// PidFilePath donne le chemin du fichier pid associé à un fichier d'état.
func PidFilePath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "omnid.pid")
}

func writePidFile(statePath string) {
	_ = os.WriteFile(PidFilePath(statePath), []byte(strconv.Itoa(os.Getpid())), 0o644)
}

func removePidFile(statePath string) {
	_ = os.Remove(PidFilePath(statePath))
}
