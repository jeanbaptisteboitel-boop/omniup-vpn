// omni-server est le serveur de coordination (plan de contrôle) du VPN :
// il enrôle les machines, attribue les adresses IP du réseau overlay et
// distribue la carte des pairs. Il ne voit jamais passer le trafic —
// celui-ci circule en direct entre machines via WireGuard.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/control"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/stun"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

const usage = `omni-server — serveur de coordination OmniUp VPN

Usage :
  omni-server serve   [--addr :8080] [--state ./omni-server.json] [--tls-cert PEM --tls-key PEM]
  omni-server genkey  [--server URL] [--admin-key CLÉ] [--reusable]
  omni-server devices [--server URL] [--admin-key CLÉ]
  omni-server acl     [--server URL] [--admin-key CLÉ] [--set politique.json]

La clé admin est affichée au premier démarrage du serveur ; elle peut aussi
être fournie via la variable d'environnement OMNIUP_ADMIN_KEY.
`

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "genkey":
		err = cmdGenkey(os.Args[2:])
	case "devices":
		err = cmdDevices(os.Args[2:])
	case "acl":
		err = cmdACL(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("erreur: %v", err)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "adresse d'écoute HTTP")
	statePath := fs.String("state", "./omni-server.json", "fichier d'état du serveur")
	tlsCert := fs.String("tls-cert", "", "certificat TLS (PEM) — active HTTPS")
	tlsKey := fs.String("tls-key", "", "clé privée TLS (PEM)")
	stunAddr := fs.String("stun-addr", ":3478", "adresse d'écoute STUN (UDP) ; \"off\" pour désactiver")
	fs.Parse(args)

	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("--tls-cert et --tls-key vont ensemble")
	}

	store, adminCreated, err := control.OpenStore(*statePath)
	if err != nil {
		return err
	}
	if adminCreated {
		log.Printf("première initialisation — clé admin : %s", store.AdminKey())
		log.Printf("conservez-la : elle permet de créer des clés d'enrôlement (genkey)")
	}

	// Service STUN : permet aux agents de découvrir leur endpoint public
	// depuis leur socket WireGuard (découverte du mapping NAT).
	if *stunAddr != "off" {
		pc, err := net.ListenPacket("udp", *stunAddr)
		if err != nil {
			return fmt.Errorf("écoute STUN sur %s: %w", *stunAddr, err)
		}
		go func() {
			if err := stun.Serve(context.Background(), pc); err != nil {
				log.Printf("stun: %v", err)
			}
		}()
		log.Printf("service STUN à l'écoute sur %s (UDP)", *stunAddr)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           control.NewServer(store).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if *tlsCert != "" {
		log.Printf("serveur de coordination à l'écoute sur %s en HTTPS (réseau %s)", *addr, control.NetworkCIDR)
		return srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	}
	log.Printf("serveur de coordination à l'écoute sur %s (réseau %s)", *addr, control.NetworkCIDR)
	log.Printf("attention : HTTP en clair — utilisez --tls-cert/--tls-key ou un reverse proxy TLS en production")
	return srv.ListenAndServe()
}

func cmdGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "URL du serveur de coordination")
	adminKey := fs.String("admin-key", os.Getenv("OMNIUP_ADMIN_KEY"), "clé admin du serveur")
	reusable := fs.Bool("reusable", false, "clé réutilisable (plusieurs machines)")
	fs.Parse(args)

	var resp types.AuthKeyResponse
	url := fmt.Sprintf("%s/api/v1/authkeys?reusable=%t", *server, *reusable)
	if err := adminCall("POST", url, *adminKey, nil, &resp); err != nil {
		return err
	}
	fmt.Println(resp.Key)
	return nil
}

func cmdDevices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "URL du serveur de coordination")
	adminKey := fs.String("admin-key", os.Getenv("OMNIUP_ADMIN_KEY"), "clé admin du serveur")
	fs.Parse(args)

	var peers []types.Peer
	if err := adminCall("GET", *server+"/api/v1/devices", *adminKey, nil, &peers); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tMACHINE\tÉTAT\tENDPOINT\tDERNIÈRE ACTIVITÉ")
	for _, p := range peers {
		state := "hors ligne"
		if p.Online {
			state = "en ligne"
		}
		last := "jamais"
		if !p.LastSeen.IsZero() {
			last = p.LastSeen.Local().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.IP, p.Hostname, state, p.Endpoint, last)
	}
	return tw.Flush()
}

// cmdACL affiche la politique d'accès courante, ou la remplace avec --set.
func cmdACL(args []string) error {
	fs := flag.NewFlagSet("acl", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "URL du serveur de coordination")
	adminKey := fs.String("admin-key", os.Getenv("OMNIUP_ADMIN_KEY"), "clé admin du serveur")
	setFile := fs.String("set", "", "fichier JSON de politique à appliquer")
	fs.Parse(args)

	var policy control.ACLPolicy
	if *setFile != "" {
		data, err := os.ReadFile(*setFile)
		if err != nil {
			return err
		}
		if err := adminCall("PUT", *server+"/api/v1/acl", *adminKey, bytes.NewReader(data), &policy); err != nil {
			return err
		}
		fmt.Printf("politique appliquée (%d règle(s))\n", len(policy.Rules))
		return nil
	}

	if err := adminCall("GET", *server+"/api/v1/acl", *adminKey, nil, &policy); err != nil {
		return err
	}
	out, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	if len(policy.Rules) == 0 {
		fmt.Println("(aucune règle : tout le trafic est autorisé)")
	}
	return nil
}

func adminCall(method, url, adminKey string, body io.Reader, out any) error {
	if adminKey == "" {
		return fmt.Errorf("clé admin requise (--admin-key ou OMNIUP_ADMIN_KEY)")
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var apiErr types.ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("serveur: %s (HTTP %d)", apiErr.Error, resp.StatusCode)
		}
		return fmt.Errorf("serveur: HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
