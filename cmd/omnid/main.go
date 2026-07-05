// omnid est l'agent OmniUp VPN : il enregistre la machine auprès du serveur
// de coordination, fait tourner WireGuard en espace utilisateur (aucun
// module noyau requis) et maintient la liste des pairs à jour, avec
// découverte STUN et perçage NAT. Nécessite root (TUN + adressage) sous Linux.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/agent"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

// version est injectée au build (-ldflags "-X main.version=v1.2.3").
var version = "dev"

const usage = `omnid — agent OmniUp VPN

Usage :
  omnid up     --server URL --auth-key CLÉ [--hostname NOM] [--iface omni0] [--port 41641]
               [--mtu 1280] [--stun hôte:3478,...] [--relay hôte:3479] [--dns=true] [--dns-zone omni]
  omnid status
  omnid down

Options communes :
  --state CHEMIN   fichier d'identité de la machine (défaut : /var/lib/omniup/omnid.json)

« up » tourne au premier plan : lancez-le sous systemd ou avec & pour le
laisser en tâche de fond. L'interface disparaît à l'arrêt du démon ;
« omnid down » arrête le démon en cours.
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
	case "version":
		fmt.Println(version)
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
	iface := fs.String("iface", "omni0", "nom de l'interface")
	port := fs.Int("port", 41641, "port d'écoute UDP WireGuard")
	mtu := fs.Int("mtu", wgnet.DefaultMTU, "MTU de l'interface")
	stunList := fs.String("stun", "", "serveurs STUN hôte:port séparés par des virgules (défaut : serveur de coordination, port 3478)")
	relaySrv := fs.String("relay", "", "relais de secours hôte:port (défaut : serveur de coordination, port 3479 ; \"off\" pour désactiver)")
	statePath := fs.String("state", defaultStatePath(), "fichier d'identité de la machine")
	dnsOn := fs.Bool("dns", true, "activer le DNS interne sur l'adresse overlay")
	dnsZone := fs.String("dns-zone", "omni", "zone du DNS interne (<machine>.<zone>)")
	fs.Parse(args)

	var stunServers []string
	if *stunList != "" {
		for _, s := range strings.Split(*stunList, ",") {
			if s = strings.TrimSpace(s); s != "" {
				stunServers = append(stunServers, s)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return agent.Up(ctx, agent.Options{
		ServerURL:   *server,
		AuthKey:     *authKey,
		Hostname:    *hostname,
		Iface:       *iface,
		ListenPort:  *port,
		MTU:         *mtu,
		StatePath:   *statePath,
		STUNServers: stunServers,
		RelayServer: *relaySrv,
		DNS:         *dnsOn,
		DNSZone:     *dnsZone,
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

	dev, err := wgnet.QueryStatus(st.Iface)
	if err != nil {
		fmt.Printf("interface  : inactive (%v)\n", err)
		return nil
	}
	fmt.Printf("interface  : active, port %d, %d pair(s)\n", dev.ListenPort, len(dev.Peers))

	// Corrélation clé publique → nom via la carte du réseau.
	names := map[string]string{}
	ips := map[string]string{}
	if nm, err := agent.NewClient(st.ServerURL, st.DeviceToken).Poll(
		types.PollRequest{ListenPort: st.ListenPort}); err == nil {
		for _, p := range nm.Peers {
			names[p.PublicKey] = p.Hostname
			ips[p.PublicKey] = p.IP
		}
	}

	for _, p := range dev.Peers {
		name := names[p.PublicKey]
		if name == "" && len(p.PublicKey) > 12 {
			name = p.PublicKey[:12] + "…"
		}
		hs := "jamais de handshake"
		if !p.LastHandshake.IsZero() {
			hs = fmt.Sprintf("handshake il y a %s", time.Since(p.LastHandshake).Round(time.Second))
		}
		ep := p.Endpoint
		if ep == "" {
			ep = "endpoint inconnu"
		}
		fmt.Printf("  pair %s (%s) — %s, via %s, rx %d o / tx %d o\n",
			name, ips[p.PublicKey], hs, ep, p.RxBytes, p.TxBytes)
	}
	return nil
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath(), "fichier d'identité de la machine")
	fs.Parse(args)

	pidPath := agent.PidFilePath(*statePath)
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("aucun démon omnid en cours (pas de %s)", pidPath)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("fichier pid corrompu: %w", err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("arrêt du démon (pid %d): %w", pid, err)
	}
	fmt.Printf("démon omnid arrêté (pid %d) — l'interface disparaît avec lui\n", pid)
	return nil
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
