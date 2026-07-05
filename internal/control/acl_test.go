package control

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

func TestACLAllows(t *testing.T) {
	alpha := Device{Hostname: "alpha", IP: "100.64.0.1"}
	beta := Device{Hostname: "beta", IP: "100.64.0.2"}
	gamma := Device{Hostname: "gamma", IP: "100.64.0.3"}

	var nilPolicy *ACLPolicy
	if !nilPolicy.Allows(alpha, beta) || !nilPolicy.Visible(alpha, beta) {
		t.Fatal("sans politique, tout doit être autorisé")
	}
	empty := &ACLPolicy{}
	if !empty.Allows(alpha, beta) {
		t.Fatal("politique vide : tout doit être autorisé")
	}

	p := &ACLPolicy{Rules: []ACLRule{
		{Src: []string{"alpha"}, Dst: []string{"100.64.0.2"}},
	}}
	if !p.Allows(alpha, beta) {
		t.Fatal("alpha→beta devrait être autorisé (nom → IP)")
	}
	if p.Allows(beta, alpha) {
		t.Fatal("beta→alpha ne devrait pas être autorisé")
	}
	if !p.Visible(beta, alpha) {
		t.Fatal("beta et alpha doivent se voir : un sens est autorisé")
	}
	if p.Allows(alpha, gamma) || p.Visible(alpha, gamma) {
		t.Fatal("gamma ne devrait pas être joignable")
	}

	wildcard := &ACLPolicy{Rules: []ACLRule{{Src: []string{"*"}, Dst: []string{"gamma"}}}}
	if !wildcard.Allows(beta, gamma) || wildcard.Allows(beta, alpha) {
		t.Fatal("le joker src doit autoriser tout le monde vers gamma uniquement")
	}
}

func TestACLValidate(t *testing.T) {
	bad := &ACLPolicy{Rules: []ACLRule{{Src: []string{"alpha"}}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("une règle sans dst devrait être rejetée")
	}
	good := &ACLPolicy{Rules: []ACLRule{{Src: []string{"*"}, Dst: []string{"*"}}}}
	if err := good.Validate(); err != nil {
		t.Fatalf("règle valide rejetée: %v", err)
	}
}

func TestNetMapFilteredByACL(t *testing.T) {
	ts, store := newTestServer(t)

	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys?reusable=true", store.AdminKey(), nil, &keyResp)

	var alpha, beta, gamma types.RegisterResponse
	for name, reg := range map[string]*types.RegisterResponse{"alpha": &alpha, "beta": &beta, "gamma": &gamma} {
		doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
			AuthKey: keyResp.Key, Hostname: name, PublicKey: genPubKey(t),
		}, reg)
	}

	// Politique : seul alpha→beta est autorisé.
	policy := `{"rules":[{"src":["alpha"],"dst":["beta"]}]}`
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/acl", strings.NewReader(policy))
	req.Header.Set("Authorization", "Bearer "+store.AdminKey())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT acl: HTTP %d", resp.StatusCode)
	}

	// alpha voit beta (et seulement beta).
	var nm types.NetMap
	doJSON(t, "POST", ts.URL+"/api/v1/poll", alpha.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if len(nm.Peers) != 1 || nm.Peers[0].Hostname != "beta" {
		t.Fatalf("alpha devrait voir uniquement beta: %+v", nm.Peers)
	}
	// beta voit alpha (sens inverse d'une règle autorisée → tunnel requis).
	doJSON(t, "POST", ts.URL+"/api/v1/poll", beta.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if len(nm.Peers) != 1 || nm.Peers[0].Hostname != "alpha" {
		t.Fatalf("beta devrait voir uniquement alpha: %+v", nm.Peers)
	}
	// gamma ne voit personne.
	doJSON(t, "POST", ts.URL+"/api/v1/poll", gamma.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if len(nm.Peers) != 0 {
		t.Fatalf("gamma ne devrait voir personne: %+v", nm.Peers)
	}

	// La politique doit survivre à un rechargement du store.
	store2, _, err := OpenStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if p := store2.ACL(); p == nil || len(p.Rules) != 1 {
		t.Fatalf("politique perdue à la réouverture: %+v", p)
	}
}
