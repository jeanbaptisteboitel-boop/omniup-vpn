package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// userClient : client HTTP avec cookies (comme un navigateur).
func userClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func doUser(t *testing.T, c *http.Client, method, url string, body, out any) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
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

func TestUserLifecycle(t *testing.T) {
	ts, store := newTestServer(t)
	c := userClient(t)

	// Sans invitation valide, l'inscription est refusée.
	resp := doUser(t, c, "POST", ts.URL+"/api/v1/users/register",
		types.UserRegisterRequest{Email: "jb@omniup.fr", Password: "motdepasse", Invite: "ominv-bidon"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invitation bidon : attendu 400, obtenu %d", resp.StatusCode)
	}

	// L'admin crée une invitation, l'inscription passe (et ouvre la session).
	var inv types.InviteResponse
	doJSON(t, "POST", ts.URL+"/api/v1/invites", store.AdminKey(), nil, &inv)
	resp = doUser(t, c, "POST", ts.URL+"/api/v1/users/register",
		types.UserRegisterRequest{Email: "JB@omniup.fr", Password: "motdepasse", Invite: inv.Code}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inscription: HTTP %d", resp.StatusCode)
	}

	// L'invitation est consommée.
	resp = doUser(t, userClient(t), "POST", ts.URL+"/api/v1/users/register",
		types.UserRegisterRequest{Email: "autre@omniup.fr", Password: "motdepasse", Invite: inv.Code}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invitation consommée : attendu 400, obtenu %d", resp.StatusCode)
	}

	// Le profil est accessible via le cookie (e-mail normalisé).
	var me types.UserProfile
	doUser(t, c, "GET", ts.URL+"/api/v1/users/me", nil, &me)
	if me.Email != "jb@omniup.fr" || len(me.Machines) != 0 {
		t.Fatalf("profil inattendu: %+v", me)
	}

	// L'utilisateur génère SA clé ; la machine enrôlée lui appartient.
	var key types.AuthKeyResponse
	doUser(t, c, "POST", ts.URL+"/api/v1/users/authkeys?reusable=false", nil, &key)
	if key.Key == "" || key.ExpiresAt.IsZero() {
		t.Fatalf("clé utilisateur inattendue: %+v", key)
	}
	var reg types.RegisterResponse
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: key.Key, Hostname: "portable-jb", PublicKey: genPubKey(t),
	}, &reg)
	doUser(t, c, "GET", ts.URL+"/api/v1/users/me", nil, &me)
	if len(me.Machines) != 1 || me.Machines[0].Owner != "jb@omniup.fr" {
		t.Fatalf("la machine devrait être rattachée au compte: %+v", me.Machines)
	}

	// L'utilisateur retire sa machine ; son jeton meurt.
	resp = doUser(t, c, "DELETE", ts.URL+"/api/v1/users/devices/portable-jb", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retrait: HTTP %d", resp.StatusCode)
	}
	resp = doJSON(t, "POST", ts.URL+"/api/v1/poll", reg.DeviceToken, types.PollRequest{ListenPort: 1}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("le jeton d'une machine retirée devrait être refusé: %d", resp.StatusCode)
	}

	// Déconnexion : le profil n'est plus accessible.
	doUser(t, c, "POST", ts.URL+"/api/v1/users/logout", nil, nil)
	resp = doUser(t, c, "GET", ts.URL+"/api/v1/users/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("après logout : attendu 401, obtenu %d", resp.StatusCode)
	}

	// Reconnexion par mot de passe.
	resp = doUser(t, c, "POST", ts.URL+"/api/v1/users/login",
		types.UserLoginRequest{Email: "jb@omniup.fr", Password: "motdepasse"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: HTTP %d", resp.StatusCode)
	}
	resp = doUser(t, userClient(t), "POST", ts.URL+"/api/v1/users/login",
		types.UserLoginRequest{Email: "jb@omniup.fr", Password: "mauvais-mdp"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mauvais mot de passe : attendu 401, obtenu %d", resp.StatusCode)
	}
}

func TestUserCannotTouchOthersDevices(t *testing.T) {
	ts, store := newTestServer(t)

	// Machine d'alice (via clé admin rattachée).
	keyAlice, err := store.CreateAuthKeyFor("alice@omniup.fr", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	doJSON(t, "POST", ts.URL+"/api/v1/register", "", types.RegisterRequest{
		AuthKey: keyAlice.Key, Hostname: "pc-alice", PublicKey: genPubKey(t),
	}, nil)

	// bob s'inscrit et tente de retirer la machine d'alice.
	var inv types.InviteResponse
	doJSON(t, "POST", ts.URL+"/api/v1/invites", store.AdminKey(), nil, &inv)
	bob := userClient(t)
	doUser(t, bob, "POST", ts.URL+"/api/v1/users/register",
		types.UserRegisterRequest{Email: "bob@omniup.fr", Password: "motdepasse", Invite: inv.Code}, nil)

	resp := doUser(t, bob, "DELETE", ts.URL+"/api/v1/users/devices/pc-alice", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob ne devrait pas pouvoir retirer la machine d'alice: %d", resp.StatusCode)
	}
	if len(store.Devices()) != 1 {
		t.Fatal("la machine d'alice devrait toujours exister")
	}
	// Et il ne la voit pas dans son profil.
	var me types.UserProfile
	doUser(t, bob, "GET", ts.URL+"/api/v1/users/me", nil, &me)
	if len(me.Machines) != 0 {
		t.Fatalf("bob ne devrait voir aucune machine: %+v", me.Machines)
	}
}

func TestOpenRegistration(t *testing.T) {
	store, _, err := OpenStore(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store)
	srv.SetOpenRegistration(true)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	c := userClient(t)
	resp := doUser(t, c, "POST", ts.URL+"/api/v1/users/register",
		types.UserRegisterRequest{Email: "libre@omniup.fr", Password: "motdepasse"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inscription ouverte : HTTP %d", resp.StatusCode)
	}

	var cfg map[string]string
	doUser(t, c, "GET", ts.URL+"/api/v1/users/config", nil, &cfg)
	if cfg["registration"] != "open" {
		t.Fatalf("config inattendue: %v", cfg)
	}
}

func TestWeakPasswordAndDuplicate(t *testing.T) {
	store, _, err := OpenStore(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterUser("x@y.fr", "court", "", false); err == nil {
		t.Fatal("mot de passe trop court accepté")
	}
	if _, err := store.RegisterUser("x@y.fr", "assez-long", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterUser("X@Y.FR", "assez-long2", "", false); err == nil {
		t.Fatal("doublon d'adresse accepté (casse différente)")
	}
}

func TestSessionPersistsAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/state.json"
	store, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	u, err := store.RegisterUser("jb@omniup.fr", "motdepasse", "", false)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateSession(u.ID)
	if err != nil {
		t.Fatal(err)
	}

	store2, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := store2.SessionUser(token); !ok || got.Email != "jb@omniup.fr" {
		t.Fatal("la session devrait survivre au redémarrage du serveur")
	}
	if _, ok := store2.SessionUser("omsess-inconnu"); ok {
		t.Fatal("session inconnue acceptée")
	}
	_ = time.Now()
}
