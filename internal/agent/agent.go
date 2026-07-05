// Package agent implémente la logique du démon omnid : enregistrement
// auprès du serveur de coordination, configuration de l'interface
// WireGuard et synchronisation périodique des pairs.
package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/dnssrv"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

// PollInterval : fréquence de synchronisation avec le serveur de coordination.
const PollInterval = 10 * time.Second

// Options configure le démarrage de l'agent.
type Options struct {
	ServerURL  string
	AuthKey    string
	Hostname   string
	Iface      string
	ListenPort int
	StatePath  string
	DNS        bool   // activer le DNS interne sur l'adresse overlay
	DNSZone    string // zone interne, ex: "omni"
}

// Up enregistre la machine si nécessaire, monte l'interface WireGuard et
// boucle jusqu'à annulation du contexte en synchronisant les pairs.
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

	if err := wgnet.EnsureInterface(st.Iface, st.IP, st.CIDR); err != nil {
		return err
	}
	log.Printf("interface %s active (%s)", st.Iface, st.IP)

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

	client := NewClient(st.ServerURL, st.DeviceToken)
	sync := func() {
		nm, err := client.Poll(st.ListenPort)
		if err != nil {
			log.Printf("poll: %v", err)
			return
		}
		if err := wgnet.Configure(st.Iface, priv, st.ListenPort, nm.Peers); err != nil {
			log.Printf("configuration wireguard: %v", err)
			return
		}
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
			log.Printf("arrêt de l'agent (l'interface %s reste montée ; « omnid down » pour la retirer)", st.Iface)
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
