// omnid est l'agent OmniUp VPN : il enregistre la machine auprès du serveur
// de coordination, monte l'interface WireGuard et maintient la liste des
// pairs à jour. Nécessite root (configuration réseau) sous Linux.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/agent"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

const usage = `omnid — agent OmniUp VPN

Usage :
  omnid up     --server URL --auth-key CLÉ [--hostname NOM] [--iface omni0] [--port 41641]
               [--dns=true] [--dns-zone omni]
  omnid status
  omnid down

Options communes :
  --state CHEMIN   fichier d'identité de la machine (défaut : /var/lib/omniup/omnid.json)

« up » tourne au premier plan : lancez-le sous systemd ou avec & pour le
laisser en tâche de fond.
`

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "down":
		err = cmdDown(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("erreur: %v", err)
	}
}

func defaultStatePath() string {
	return "/var/lib/omniup/omnid.json"
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	server := fs.String("server", "", "URL du serveur de coordination (ex: https://vpn.example.com)")
	authKey := fs.String("auth-key", "", "clé d'enrôlement (requise à la première connexion)")
	hostname := fs.String("hostname", defaultHostname(), "nom de la machine sur le réseau")
	iface := fs.String("iface", "omni0", "nom de l'interface WireGuard")
	port := fs.Int("port", 41641, "port d'écoute UDP WireGuard")
	statePath := fs.String("state", defaultStatePath(), "fichier d'identité de la machine")
	dnsOn := fs.Bool("dns", true, "activer le DNS interne sur l'adresse overlay")
	dnsZone := fs.String("dns-zone", "omni", "zone du DNS interne (<machine>.<zone>)")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return agent.Up(ctx, agent.Options{
		ServerURL:  *server,
		AuthKey:    *authKey,
		Hostname:   *hostname,
		Iface:      *iface,
		ListenPort: *port,
		StatePath:  *statePath,
		DNS:        *dnsOn,
		DNSZone:    *dnsZone,
	})
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath(), "fichier d'identité de la machine")
	fs.Parse(args)

	st, err := agent.LoadState(*statePath)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("aucune identité : lancez d'abord « omnid up »")
	}

	fmt.Printf("machine    : %s (%s)\n", st.IP, st.Iface)
	fmt.Printf("serveur    : %s\n", st.ServerURL)

	dev, err := wgnet.DeviceInfo(st.Iface)
	if err != nil {
		fmt.Printf("interface  : inactive (%v)\n", err)
		return nil
	}
	fmt.Printf("interface  : active, port %d, %d pair(s)\n", dev.ListenPort, len(dev.Peers))

	// Corrélation clé publique → nom via la carte du réseau.
	names := map[string]string{}
	ips := map[string]string{}
	if nm, err := agent.NewClient(st.ServerURL, st.DeviceToken).Poll(st.ListenPort); err == nil {
		for _, p := range nm.Peers {
			names[p.PublicKey] = p.Hostname
			ips[p.PublicKey] = p.IP
		}
	}

	for _, p := range dev.Peers {
		pub := p.PublicKey.String()
		name := names[pub]
		if name == "" {
			name = pub[:12] + "…"
		}
		hs := "jamais de handshake"
		if !p.LastHandshakeTime.IsZero() {
			hs = fmt.Sprintf("handshake il y a %s", time.Since(p.LastHandshakeTime).Round(time.Second))
		}
		fmt.Printf("  pair %s (%s) — %s, rx %d o / tx %d o\n",
			name, ips[pub], hs, p.ReceiveBytes, p.TransmitBytes)
	}
	return nil
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath(), "fichier d'identité de la machine")
	iface := fs.String("iface", "", "nom de l'interface (défaut : celui de l'identité)")
	fs.Parse(args)

	name := *iface
	if name == "" {
		st, err := agent.LoadState(*statePath)
		if err != nil {
			return err
		}
		if st == nil {
			name = "omni0"
		} else {
			name = st.Iface
		}
	}
	if err := wgnet.DeleteInterface(name); err != nil {
		return err
	}
	fmt.Printf("interface %s supprimée\n", name)
	return nil
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
