package control

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

func TestSubnetRouteApproval(t *testing.T) {
	ts, store := newTestServer(t)

	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys?reusable=true", store.AdminKey(), nil, &keyResp)
	var router, client types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "routeur", PublicKey: genPubKey(t),
	}, &router)
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "client", PublicKey: genPubKey(t),
	}, &client)

	// Le routeur annonce un sous-réseau (+ une route invalide, ignorée,
	// et une non canonique, normalisée).
	doJSON(t, "POST", ts.URL+"/api/v1/poll", router.DeviceToken, types.PollRequest{
		ListenPort:       1,
		AdvertisedRoutes: []string{"192.168.50.0/24", "pas-un-cidr", "10.1.2.3/16"},
	}, nil)

	// Sans approbation : rien n'est distribué.
	var nm types.NetMap
	doJSON(t, "POST", ts.URL+"/api/v1/poll", client.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if len(nm.Peers) != 1 || len(nm.Peers[0].Routes) != 0 {
		t.Fatalf("aucune route ne devrait être distribuée avant approbation: %+v", nm.Peers)
	}

	// L'admin approuve une des deux routes (la normalisée) + une non annoncée.
	body := []byte(`{"routes":["192.168.50.0/24","172.16.0.0/12"]}`)
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/devices/routeur/routes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+store.AdminKey())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approbation: HTTP %d", resp.StatusCode)
	}

	// Seule l'intersection annoncées ∩ approuvées est distribuée.
	doJSON(t, "POST", ts.URL+"/api/v1/poll", client.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if len(nm.Peers) != 1 || len(nm.Peers[0].Routes) != 1 || nm.Peers[0].Routes[0] != "192.168.50.0/24" {
		t.Fatalf("routes distribuées inattendues: %+v", nm.Peers[0].Routes)
	}
	// 10.1.2.3/16 annoncée a été normalisée en 10.1.0.0/16.
	var devices []types.Peer
	doJSON(t, "GET", ts.URL+"/api/v1/devices", store.AdminKey(), nil, &devices)
	for _, d := range devices {
		if d.Hostname == "routeur" {
			found := false
			for _, r := range d.AdvertisedRoutes {
				if r == "10.1.0.0/16" {
					found = true
				}
				if r == "pas-un-cidr" || r == "10.1.2.3/16" {
					t.Fatalf("route non normalisée conservée: %v", d.AdvertisedRoutes)
				}
			}
			if !found {
				t.Fatalf("route normalisée absente: %v", d.AdvertisedRoutes)
			}
		}
	}

	// Approbation d'une route invalide : 400.
	req, _ = http.NewRequest("PUT", ts.URL+"/api/v1/devices/routeur/routes",
		bytes.NewReader([]byte(`{"routes":["n-importe-quoi"]}`)))
	req.Header.Set("Authorization", "Bearer "+store.AdminKey())
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("route invalide : attendu 400, obtenu %d", resp.StatusCode)
	}

	// Retrait de l'approbation : plus rien de distribué.
	req, _ = http.NewRequest("PUT", ts.URL+"/api/v1/devices/routeur/routes",
		bytes.NewReader([]byte(`{"routes":[]}`)))
	req.Header.Set("Authorization", "Bearer "+store.AdminKey())
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var nm2 types.NetMap // struct fraîche : json.Decode fusionne les champs omis
	doJSON(t, "POST", ts.URL+"/api/v1/poll", client.DeviceToken, types.PollRequest{ListenPort: 1}, &nm2)
	if len(nm2.Peers[0].Routes) != 0 {
		t.Fatalf("les routes devraient avoir disparu: %+v", nm2.Peers[0].Routes)
	}
}
