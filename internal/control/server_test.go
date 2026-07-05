package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

func newTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	store, _, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewServer(store).Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

func doJSON(t *testing.T, method, url, token string, body, out any) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp
}

func genPubKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func TestRegisterAndPoll(t *testing.T) {
	ts, store := newTestServer(t)

	// Création d'une clé d'enrôlement réutilisable via l'API admin.
	var keyResp types.AuthKeyResponse
	resp := doJSON(t, "POST", ts.URL+"/api/v1/authkeys?reusable=true", store.AdminKey(), nil, &keyResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authkeys: HTTP %d", resp.StatusCode)
	}

	// Enregistrement de deux machines.
	var reg1, reg2 types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: genPubKey(t),
	}, &reg1)
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "beta", PublicKey: genPubKey(t),
	}, &reg2)

	if reg1.IP != "100.64.0.1" || reg2.IP != "100.64.0.2" {
		t.Fatalf("IPAM inattendu: %q, %q", reg1.IP, reg2.IP)
	}
	if reg1.DeviceToken == "" || reg1.DeviceToken == reg2.DeviceToken {
		t.Fatal("jetons machine invalides")
	}

	// alpha poll : il doit voir beta dans la carte, avec un endpoint
	// construit à partir de l'IP source et du port déclaré par beta.
	doJSON(t, "POST", ts.URL+"/api/v1/poll", reg2.DeviceToken, types.PollRequest{ListenPort: 51820}, nil)

	var nm types.NetMap
	doJSON(t, "POST", ts.URL+"/api/v1/poll", reg1.DeviceToken, types.PollRequest{ListenPort: 41641}, &nm)
	if nm.Self.IP != reg1.IP {
		t.Fatalf("self attendu %s, obtenu %s", reg1.IP, nm.Self.IP)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Hostname != "beta" {
		t.Fatalf("carte inattendue: %+v", nm.Peers)
	}
	if !nm.Peers[0].Online {
		t.Fatal("beta devrait être en ligne juste après son poll")
	}
	if nm.Peers[0].Endpoint == "" {
		t.Fatal("l'endpoint de beta devrait être renseigné après son poll")
	}
}

func TestSingleUseAuthKey(t *testing.T) {
	ts, store := newTestServer(t)

	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys", store.AdminKey(), nil, &keyResp)
	if keyResp.Reusable {
		t.Fatal("la clé devrait être à usage unique par défaut")
	}

	resp := doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: genPubKey(t),
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("premier enregistrement refusé: HTTP %d", resp.StatusCode)
	}

	resp = doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "beta", PublicKey: genPubKey(t),
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("la clé à usage unique aurait dû être refusée: HTTP %d", resp.StatusCode)
	}
}

func TestReRegisterIsIdempotent(t *testing.T) {
	ts, store := newTestServer(t)

	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys", store.AdminKey(), nil, &keyResp)

	pub := genPubKey(t)
	var reg1, reg2 types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: pub,
	}, &reg1)
	// Même clé publique, clé d'auth déjà consommée : doit renvoyer la même identité.
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: pub,
	}, &reg2)

	if reg1.IP != reg2.IP || reg1.DeviceID != reg2.DeviceID {
		t.Fatalf("le ré-enregistrement devrait être idempotent: %+v vs %+v", reg1, reg2)
	}
}

func TestAdminAuthRequired(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := doJSON(t, "POST", ts.URL+"/api/v1/authkeys", "mauvaise-clé", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("attendu 401, obtenu %d", resp.StatusCode)
	}
	resp = doJSON(t, "GET", ts.URL+"/api/v1/devices", "", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("attendu 401, obtenu %d", resp.StatusCode)
	}
}

func TestStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, created, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("la clé admin devrait être créée au premier démarrage")
	}
	admin := store.AdminKey()
	key, err := store.CreateAuthKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterDevice(key.Key, "alpha", genPubKey(t)); err != nil {
		t.Fatal(err)
	}

	// Réouverture : tout doit être conservé.
	store2, created, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("la clé admin ne devrait pas être recréée")
	}
	if store2.AdminKey() != admin {
		t.Fatal("clé admin perdue à la réouverture")
	}
	if devs := store2.Devices(); len(devs) != 1 || devs[0].Hostname != "alpha" {
		t.Fatalf("machines perdues à la réouverture: %+v", devs)
	}
}
