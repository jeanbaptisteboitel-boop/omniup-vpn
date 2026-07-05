package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestAuthKeyExpiry(t *testing.T) {
	store, _, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Clé à durée de vie minuscule : refusée une fois expirée.
	key, err := store.CreateAuthKey(true, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if key.ExpiresAt.IsZero() {
		t.Fatal("la clé devrait porter une date d'expiration")
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := store.RegisterDevice(key.Key, "tard", genPubKey(t)); err == nil {
		t.Fatal("une clé expirée devrait être refusée")
	}
	// Clé sans expiration : toujours valide.
	forever, err := store.CreateAuthKey(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !forever.ExpiresAt.IsZero() {
		t.Fatal("ttl 0 devrait signifier sans expiration")
	}
	if _, err := store.RegisterDevice(forever.Key, "ok", genPubKey(t)); err != nil {
		t.Fatalf("clé sans expiration refusée: %v", err)
	}
}

func TestAuthKeyTTLParam(t *testing.T) {
	ts, store := newTestServer(t)
	var keyResp types.AuthKeyResponse
	resp := doJSON(t, "POST", ts.URL+"/api/v1/authkeys?ttl=30m", store.AdminKey(), nil, &keyResp)
	if resp.StatusCode != http.StatusOK || keyResp.ExpiresAt.IsZero() {
		t.Fatalf("ttl=30m: HTTP %d, expiration %v", resp.StatusCode, keyResp.ExpiresAt)
	}
	resp = doJSON(t, "POST", ts.URL+"/api/v1/authkeys?ttl=n-importe-quoi", store.AdminKey(), nil, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("ttl invalide: attendu 400, obtenu %d", resp.StatusCode)
	}
}

func TestTokenRotation(t *testing.T) {
	old := TokenRotateAfter
	TokenRotateAfter = 0 // chaque poll déclenche une rotation
	t.Cleanup(func() { TokenRotateAfter = old })

	ts, store := newTestServer(t)
	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys", store.AdminKey(), nil, &keyResp)
	var reg types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: genPubKey(t),
	}, &reg)

	var nm types.NetMap
	doJSON(t, "POST", ts.URL+"/api/v1/poll", reg.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if nm.NewToken == "" || nm.NewToken == reg.DeviceToken {
		t.Fatalf("le poll devrait renvoyer un nouveau jeton: %q", nm.NewToken)
	}

	// L'ancien jeton reste toléré pendant la grâce (une génération)…
	var nm2 types.NetMap
	resp := doJSON(t, "POST", ts.URL+"/api/v1/poll", reg.DeviceToken, types.PollRequest{ListenPort: 1}, &nm2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("l'ancien jeton devrait être toléré pendant la grâce: HTTP %d", resp.StatusCode)
	}
	// …et le jeton le plus récent fonctionne.
	latest := nm2.NewToken
	if latest == "" {
		latest = nm.NewToken
	}
	resp = doJSON(t, "POST", ts.URL+"/api/v1/poll", latest, types.PollRequest{ListenPort: 1}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("le dernier jeton devrait être accepté: HTTP %d", resp.StatusCode)
	}
	// Deux générations en arrière : refusé.
	resp = doJSON(t, "POST", ts.URL+"/api/v1/poll", reg.DeviceToken, types.PollRequest{ListenPort: 1}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("un jeton de deux générations devrait être refusé: HTTP %d", resp.StatusCode)
	}

	// Un jeton fantaisiste reste refusé.
	resp = doJSON(t, "POST", ts.URL+"/api/v1/poll", "omtok-bidon", types.PollRequest{ListenPort: 1}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("jeton invalide: attendu 401, obtenu %d", resp.StatusCode)
	}
}

func TestRevokeDevice(t *testing.T) {
	ts, store := newTestServer(t)

	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys?reusable=true", store.AdminKey(), nil, &keyResp)

	var alpha, beta types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: genPubKey(t),
	}, &alpha)
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "beta", PublicKey: genPubKey(t),
	}, &beta)

	// Révocation par nom.
	resp := doJSON(t, "DELETE", ts.URL+"/api/v1/devices/beta", store.AdminKey(), nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("révocation: HTTP %d", resp.StatusCode)
	}

	// Le jeton de beta ne vaut plus rien.
	resp = doJSON(t, "POST", ts.URL+"/api/v1/poll", beta.DeviceToken, types.PollRequest{ListenPort: 1}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("le jeton révoqué devrait être refusé: HTTP %d", resp.StatusCode)
	}

	// alpha ne voit plus beta.
	var nm types.NetMap
	doJSON(t, "POST", ts.URL+"/api/v1/poll", alpha.DeviceToken, types.PollRequest{ListenPort: 1}, &nm)
	if len(nm.Peers) != 0 {
		t.Fatalf("beta devrait avoir disparu de la carte: %+v", nm.Peers)
	}

	// Cible inconnue : 404.
	resp = doJSON(t, "DELETE", ts.URL+"/api/v1/devices/fantome", store.AdminKey(), nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("attendu 404, obtenu %d", resp.StatusCode)
	}
}

func TestCustomCIDR(t *testing.T) {
	store, _, err := OpenStoreCIDR(filepath.Join(t.TempDir(), "state.json"), "10.42.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateAuthKey(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	// /30 : deux hôtes utilisables (10.42.0.1 et 10.42.0.2).
	d1, err := store.RegisterDevice(key.Key, "un", genPubKey(t))
	if err != nil || d1.IP != "10.42.0.1" {
		t.Fatalf("première allocation: %v, %v", d1, err)
	}
	d2, err := store.RegisterDevice(key.Key, "deux", genPubKey(t))
	if err != nil || d2.IP != "10.42.0.2" {
		t.Fatalf("deuxième allocation: %v, %v", d2, err)
	}
	if _, err := store.RegisterDevice(key.Key, "trois", genPubKey(t)); err == nil {
		t.Fatal("la plage /30 devrait être épuisée (réseau et broadcast exclus)")
	}
	// Une adresse libérée par révocation est réattribuable.
	if _, err := store.RemoveDevice("10.42.0.1"); err != nil {
		t.Fatal(err)
	}
	d4, err := store.RegisterDevice(key.Key, "quatre", genPubKey(t))
	if err != nil || d4.IP != "10.42.0.1" {
		t.Fatalf("réallocation après révocation: %v, %v", d4, err)
	}
}

func TestCIDRIsSticky(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if _, _, err := OpenStoreCIDR(path, "10.42.0.0/24"); err != nil {
		t.Fatal(err)
	}
	// Réouverture avec une autre plage : celle de l'état fait foi.
	store, _, err := OpenStoreCIDR(path, "192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if store.CIDR() != "10.42.0.0/24" {
		t.Fatalf("la plage devrait être figée: %s", store.CIDR())
	}
	if _, _, err := OpenStoreCIDR(path, "pas-un-cidr"); err == nil {
		t.Fatal("cidr invalide accepté")
	}
}

func TestInfoAndAuthKeyList(t *testing.T) {
	ts, store := newTestServer(t)

	var keyResp types.AuthKeyResponse
	doJSON(t, "POST", ts.URL+"/api/v1/authkeys?reusable=true&ttl=1h", store.AdminKey(), nil, &keyResp)
	var reg types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyResp.Key, Hostname: "alpha", PublicKey: genPubKey(t),
	}, &reg)
	doJSON(t, "POST", ts.URL+"/api/v1/poll", reg.DeviceToken, types.PollRequest{ListenPort: 1}, nil)

	var info types.InfoResponse
	doJSON(t, "GET", ts.URL+"/api/v1/info", store.AdminKey(), nil, &info)
	if info.CIDR != DefaultCIDR || info.DeviceCount != 1 || info.OnlineCount != 1 {
		t.Fatalf("info inattendue: %+v", info)
	}

	var keys []types.AuthKeyInfo
	doJSON(t, "GET", ts.URL+"/api/v1/authkeys", store.AdminKey(), nil, &keys)
	if len(keys) != 1 || !keys[0].Reusable || keys[0].ExpiresAt.IsZero() {
		t.Fatalf("liste de clés inattendue: %+v", keys)
	}
	if keys[0].KeyMasked == keyResp.Key || !strings.Contains(keys[0].KeyMasked, "…") {
		t.Fatalf("la clé devrait être masquée: %q", keys[0].KeyMasked)
	}
}

func TestWebUIServed(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin: HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("type inattendu: %s", ct)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "OmniUp VPN") {
		t.Fatal("la console devrait contenir le titre attendu")
	}

	// La racine redirige vers /admin.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp2, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound || resp2.Header.Get("Location") != "/admin" {
		t.Fatalf("la racine devrait rediriger vers /admin: %d %s", resp2.StatusCode, resp2.Header.Get("Location"))
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
	key, err := store.CreateAuthKey(false, 0)
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
