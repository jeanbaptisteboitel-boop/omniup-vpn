package agent

import (
	"testing"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

func TestAdvertisedRoutesValidation(t *testing.T) {
	adv, mine, err := advertisedRoutes(Options{
		AdvertiseRoutes:   []string{"192.168.1.5/24", " 10.0.0.0/8 ", "192.168.1.0/24"},
		AdvertiseExitNode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Normalisation + déduplication + 0/0 de l'exit node.
	want := []string{"192.168.1.0/24", "10.0.0.0/8", "0.0.0.0/0"}
	if len(adv) != len(want) {
		t.Fatalf("annonces inattendues: %v", adv)
	}
	for i := range want {
		if adv[i] != want[i] || !mine[want[i]] {
			t.Fatalf("annonces inattendues: %v", adv)
		}
	}

	if _, _, err := advertisedRoutes(Options{AdvertiseRoutes: []string{"pas-un-cidr"}}); err == nil {
		t.Fatal("route invalide acceptée")
	}
}

func TestFilterRoutes(t *testing.T) {
	peers := []types.Peer{
		{Hostname: "routeur", IP: "100.64.0.1", Routes: []string{"192.168.50.0/24", "0.0.0.0/0"}},
		{Hostname: "autre", IP: "100.64.0.2", Routes: []string{"10.9.0.0/16", "192.168.77.0/24"}},
	}

	// Cas nominal : routes acceptées, pas d'exit node choisi.
	out, subnets, exitFound := filterRoutes(peers, Options{AcceptRoutes: true}, map[string]bool{})
	if exitFound {
		t.Fatal("aucun exit node demandé : exitFound devrait être faux")
	}
	if len(out[0].Routes) != 1 || out[0].Routes[0] != "192.168.50.0/24" {
		t.Fatalf("0.0.0.0/0 devrait être filtré sans --exit-node: %v", out[0].Routes)
	}
	if len(subnets) != 3 {
		t.Fatalf("3 sous-réseaux attendus, obtenu %v", subnets)
	}

	// Exit node choisi par nom : 0/0 gardé pour lui seul.
	out, _, exitFound = filterRoutes(peers, Options{AcceptRoutes: true, ExitNode: "routeur"}, map[string]bool{})
	if !exitFound {
		t.Fatal("l'exit node devrait être trouvé")
	}
	has00 := false
	for _, r := range out[0].Routes {
		if r == "0.0.0.0/0" {
			has00 = true
		}
	}
	if !has00 {
		t.Fatalf("le pair exit node devrait garder 0.0.0.0/0: %v", out[0].Routes)
	}

	// Routes refusées : plus aucun sous-réseau (mais l'exit node reste).
	out, subnets, _ = filterRoutes(peers, Options{AcceptRoutes: false, ExitNode: "100.64.0.1"}, map[string]bool{})
	if len(subnets) != 0 || len(out[1].Routes) != 0 {
		t.Fatalf("avec accept-routes=false : %v %v", subnets, out[1].Routes)
	}

	// Nos propres routes ne sont jamais réinstallées.
	_, subnets, _ = filterRoutes(peers, Options{AcceptRoutes: true},
		map[string]bool{"10.9.0.0/16": true})
	for _, s := range subnets {
		if s == "10.9.0.0/16" {
			t.Fatal("une route que nous annonçons ne doit pas être installée")
		}
	}
}
