package control

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// fakeIdP est un fournisseur OpenID Connect minimal mais réel : découverte,
// JWKS avec une vraie clé RSA, et jetons d'identité signés RS256.
type fakeIdP struct {
	ts    *httptest.Server
	key   *rsa.PrivateKey
	email string // e-mail émis dans le prochain jeton
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, email: "jb@omniup.fr"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.ts.URL,
			"authorization_endpoint":                idp.ts.URL + "/auth",
			"token_endpoint":                        idp.ts.URL + "/token",
			"jwks_uri":                              idp.ts.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := &key.PublicKey
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
				"n": b64url(pub.N.Bytes()),
				"e": b64url(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access",
			"token_type":   "Bearer",
			"id_token":     idp.signIDToken(t, idp.email),
		})
	})
	idp.ts = httptest.NewServer(mux)
	t.Cleanup(idp.ts.Close)
	return idp
}

func (idp *fakeIdP) signIDToken(t *testing.T, email string) string {
	t.Helper()
	header := b64url([]byte(`{"alg":"RS256","kid":"test"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":            idp.ts.URL,
		"sub":            "user-1",
		"aud":            "omniup-client",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          email,
		"email_verified": true,
	})
	signingInput := header + "." + b64url(claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, 0x5, sum[:]) // 0x5 = crypto.SHA256
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + b64url(sig)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newSSOServer monte un serveur de contrôle avec le SSO branché sur le
// faux fournisseur.
func newSSOServer(t *testing.T, allowedDomain string) (*httptest.Server, *Store, *fakeIdP) {
	t.Helper()
	store, _, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	idp := newFakeIdP(t)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	err = srv.EnableOIDC(context.Background(), OIDCConfig{
		Issuer:        idp.ts.URL,
		ClientID:      "omniup-client",
		ClientSecret:  "secret",
		PublicURL:     ts.URL,
		AllowedDomain: allowedDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ts, store, idp
}

func TestSSOEnrollmentFlow(t *testing.T) {
	ts, store, _ := newSSOServer(t, "omniup.fr")

	// 1. L'agent ouvre une session d'enrôlement.
	var start types.EnrollStartResponse
	doJSON(t, "POST", ts.URL+"/api/v1/enroll/start", "", types.EnrollStartRequest{
		Hostname: "portable-jb", PublicKey: genPubKey(t),
	}, &start)
	if start.SessionID == "" || !strings.Contains(start.AuthURL, "/enroll/") {
		t.Fatalf("session invalide: %+v", start)
	}

	// 2. Tant que l'utilisateur n'a rien fait : 202.
	resp, err := http.Get(ts.URL + "/api/v1/enroll/wait?session=" + start.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("attendu 202 en attente, obtenu %d", resp.StatusCode)
	}

	// 3. L'utilisateur ouvre l'URL : redirection vers le fournisseur.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noRedirect.Get(start.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.Contains(loc, "/auth") ||
		!strings.Contains(loc, "state="+start.SessionID) {
		t.Fatalf("redirection inattendue: %d %s", resp.StatusCode, loc)
	}

	// 4. Retour du fournisseur avec un code : le serveur échange, vérifie
	//    le jeton signé et enrôle la machine.
	resp, err = http.Get(fmt.Sprintf("%s/oidc/callback?state=%s&code=fake-code", ts.URL, start.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback: HTTP %d", resp.StatusCode)
	}

	// 5. L'agent récupère son identité.
	var reg types.RegisterResponse
	doJSON(t, "GET", ts.URL+"/api/v1/enroll/wait?session="+start.SessionID, "", nil, &reg)
	if reg.IP == "" || reg.DeviceToken == "" {
		t.Fatalf("enregistrement incomplet: %+v", reg)
	}

	// La machine est rattachée à l'e-mail authentifié.
	devs := store.Devices()
	if len(devs) != 1 || devs[0].Owner != "jb@omniup.fr" || devs[0].Hostname != "portable-jb" {
		t.Fatalf("machine inattendue: %+v", devs)
	}
	// Et le jeton fonctionne.
	resp2 := doJSON(t, "POST", ts.URL+"/api/v1/poll", reg.DeviceToken, types.PollRequest{ListenPort: 1}, nil)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("le jeton SSO devrait être valide: HTTP %d", resp2.StatusCode)
	}
}

func TestSSORejectsWrongDomain(t *testing.T) {
	ts, store, idp := newSSOServer(t, "omniup.fr")
	idp.email = "intrus@ailleurs.com"

	var start types.EnrollStartResponse
	doJSON(t, "POST", ts.URL+"/api/v1/enroll/start", "", types.EnrollStartRequest{
		Hostname: "machine-intruse", PublicKey: genPubKey(t),
	}, &start)

	resp, err := http.Get(fmt.Sprintf("%s/oidc/callback?state=%s&code=x", ts.URL, start.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("un domaine étranger devrait être refusé: HTTP %d", resp.StatusCode)
	}
	if len(store.Devices()) != 0 {
		t.Fatal("aucune machine ne devrait avoir été enrôlée")
	}
	// L'agent qui attend reçoit l'échec.
	resp, _ = http.Get(ts.URL + "/api/v1/enroll/wait?session=" + start.SessionID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("l'agent devrait voir le refus: HTTP %d", resp.StatusCode)
	}
}

func TestSSOUnknownSession(t *testing.T) {
	ts, _, _ := newSSOServer(t, "")
	for _, path := range []string{
		"/api/v1/enroll/wait?session=inconnue",
		"/enroll/inconnue",
		"/oidc/callback?state=inconnue&code=x",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: attendu 404, obtenu %d", path, resp.StatusCode)
		}
	}
}

func TestSSODisabled(t *testing.T) {
	ts, _ := newTestServer(t) // serveur sans OIDC
	resp := doJSON(t, "POST", ts.URL+"/api/v1/enroll/start", "", types.EnrollStartRequest{
		Hostname: "x", PublicKey: genPubKey(t),
	}, nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("sans SSO configuré : attendu 501, obtenu %d", resp.StatusCode)
	}
}
