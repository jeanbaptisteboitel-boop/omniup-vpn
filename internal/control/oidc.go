package control

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// enrollTTL : durée de vie d'une session d'enrôlement SSO en attente.
const enrollTTL = 15 * time.Minute

// OIDCConfig configure l'enrôlement SSO (OpenID Connect).
type OIDCConfig struct {
	Issuer       string // ex: https://accounts.google.com
	ClientID     string
	ClientSecret string
	PublicURL    string // URL publique du serveur, ex: https://vpn.omniup.fr
	// Contrôle d'accès : si AllowedEmails est non vide, seuls ces e-mails
	// peuvent enrôler ; sinon si AllowedDomain est non vide, seuls les
	// e-mails de ce domaine ; sinon tout e-mail vérifié du fournisseur.
	AllowedDomain string
	AllowedEmails []string
}

type oidcProvider struct {
	cfg      OIDCConfig
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config

	mu       sync.Mutex
	sessions map[string]*enrollSession
}

type enrollSession struct {
	hostname  string
	publicKey string
	createdAt time.Time
	// renseignés à l'approbation :
	approved bool
	result   *types.RegisterResponse
	owner    string
	failure  string
}

// EnableOIDC active l'enrôlement SSO sur le serveur (découverte du
// fournisseur, validation des jetons via son JWKS).
func (s *Server) EnableOIDC(ctx context.Context, cfg OIDCConfig) error {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.PublicURL == "" {
		return fmt.Errorf("oidc : issuer, client-id, client-secret et public-url sont requis")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return fmt.Errorf("découverte OIDC de %s: %w", cfg.Issuer, err)
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	s.oidc = &oidcProvider{
		cfg:      cfg,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.PublicURL + "/oidc/callback",
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		sessions: map[string]*enrollSession{},
	}
	if len(cfg.AllowedEmails) == 0 && cfg.AllowedDomain == "" {
		log.Printf("oidc : attention, aucun filtre d'accès — tout compte %s vérifié pourra enrôler une machine", cfg.Issuer)
	}
	return nil
}

// handleEnrollStart (POST /api/v1/enroll/start) ouvre une session
// d'enrôlement et renvoie l'URL à ouvrir dans un navigateur.
func (s *Server) handleEnrollStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotImplemented, "SSO non configuré sur ce serveur (utilisez --auth-key)")
		return
	}
	var req types.EnrollStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "corps JSON invalide")
		return
	}
	if _, err := wgtypes.ParseKey(req.PublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "clé publique WireGuard invalide")
		return
	}
	if req.Hostname == "" {
		req.Hostname = "machine-sans-nom"
	}

	id := randomHex(24)
	s.oidc.mu.Lock()
	s.oidc.pruneLocked()
	s.oidc.sessions[id] = &enrollSession{
		hostname:  req.Hostname,
		publicKey: req.PublicKey,
		createdAt: time.Now(),
	}
	s.oidc.mu.Unlock()

	writeJSON(w, http.StatusOK, types.EnrollStartResponse{
		SessionID: id,
		AuthURL:   s.oidc.cfg.PublicURL + "/enroll/" + id,
	})
}

// handleEnrollWait (GET /api/v1/enroll/wait?session=…) est sondé par
// l'agent : 202 tant que l'utilisateur ne s'est pas authentifié.
func (s *Server) handleEnrollWait(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotImplemented, "SSO non configuré sur ce serveur")
		return
	}
	s.oidc.mu.Lock()
	sess, ok := s.oidc.sessions[r.URL.Query().Get("session")]
	var out *enrollSession
	if ok {
		cp := *sess
		out = &cp
	}
	s.oidc.mu.Unlock()

	switch {
	case !ok || time.Since(out.createdAt) > enrollTTL:
		writeError(w, http.StatusNotFound, "session d'enrôlement inconnue ou expirée")
	case out.failure != "":
		writeError(w, http.StatusForbidden, out.failure)
	case !out.approved:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "en attente d'authentification"})
	default:
		writeJSON(w, http.StatusOK, out.result)
	}
}

// handleEnrollRedirect (GET /enroll/{id}) — l'URL ouverte par
// l'utilisateur : redirige vers le fournisseur d'identité.
func (s *Server) handleEnrollRedirect(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	s.oidc.mu.Lock()
	sess, ok := s.oidc.sessions[id]
	valid := ok && time.Since(sess.createdAt) <= enrollTTL && !sess.approved
	s.oidc.mu.Unlock()
	if !valid {
		http.Error(w, "session d'enrôlement inconnue ou expirée — relancez « omnid up »", http.StatusNotFound)
		return
	}
	// L'identifiant de session (aléatoire, courte durée) sert de state.
	http.Redirect(w, r, s.oidc.oauth.AuthCodeURL(id), http.StatusFound)
}

// handleOIDCCallback (GET /oidc/callback) — retour du fournisseur :
// échange du code, validation du jeton, contrôle d'accès, enrôlement.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	id := r.URL.Query().Get("state")
	s.oidc.mu.Lock()
	sess, ok := s.oidc.sessions[id]
	valid := ok && time.Since(sess.createdAt) <= enrollTTL && !sess.approved
	s.oidc.mu.Unlock()
	if !valid {
		http.Error(w, "session d'enrôlement inconnue ou expirée", http.StatusNotFound)
		return
	}

	fail := func(status int, publicMsg string) {
		s.oidc.mu.Lock()
		sess.failure = publicMsg
		s.oidc.mu.Unlock()
		http.Error(w, publicMsg, status)
	}

	tok, err := s.oidc.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("oidc: échange du code: %v", err)
		fail(http.StatusBadGateway, "échec de l'échange avec le fournisseur d'identité")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		fail(http.StatusBadGateway, "le fournisseur n'a pas renvoyé de jeton d'identité")
		return
	}
	idToken, err := s.oidc.verifier.Verify(r.Context(), rawID)
	if err != nil {
		log.Printf("oidc: jeton invalide: %v", err)
		fail(http.StatusForbidden, "jeton d'identité invalide")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Email == "" {
		fail(http.StatusForbidden, "adresse e-mail absente du jeton d'identité")
		return
	}
	if claims.Verified != nil && !*claims.Verified {
		fail(http.StatusForbidden, "adresse e-mail non vérifiée chez le fournisseur")
		return
	}
	if !s.oidc.emailAllowed(claims.Email) {
		log.Printf("oidc: enrôlement refusé pour %s", claims.Email)
		fail(http.StatusForbidden, "ce compte n'est pas autorisé sur ce réseau")
		return
	}

	d, err := s.store.RegisterDeviceSSO(sess.hostname, sess.publicKey, claims.Email)
	if err != nil {
		log.Printf("oidc: enrôlement: %v", err)
		fail(http.StatusInternalServerError, "erreur interne lors de l'enrôlement")
		return
	}

	s.oidc.mu.Lock()
	sess.approved = true
	sess.owner = claims.Email
	sess.result = &types.RegisterResponse{
		DeviceID:    d.ID,
		DeviceToken: d.Token,
		IP:          d.IP,
		CIDR:        s.store.CIDR(),
	}
	s.oidc.mu.Unlock()

	log.Printf("machine enregistrée via SSO: %s (%s) pour %s", d.Hostname, d.IP, claims.Email)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>OmniUp VPN</title>
<body style="font:16px system-ui;max-width:34rem;margin:4rem auto;text-align:center">
<h2>✅ Machine connectée</h2>
<p><strong>%s</strong> a rejoint le réseau avec l'adresse <code>%s</code>,
rattachée à <strong>%s</strong>.</p>
<p>Vous pouvez fermer cet onglet et retourner au terminal.</p>`,
		htmlEscape(sess.hostname), d.IP, htmlEscape(claims.Email))
}

func (p *oidcProvider) emailAllowed(email string) bool {
	email = strings.ToLower(email)
	if len(p.cfg.AllowedEmails) > 0 {
		for _, e := range p.cfg.AllowedEmails {
			if strings.ToLower(strings.TrimSpace(e)) == email {
				return true
			}
		}
		return false
	}
	if p.cfg.AllowedDomain != "" {
		return strings.HasSuffix(email, "@"+strings.ToLower(p.cfg.AllowedDomain))
	}
	return true
}

// pruneLocked supprime les sessions expirées (mutex déjà pris).
func (p *oidcProvider) pruneLocked() {
	for id, sess := range p.sessions {
		if time.Since(sess.createdAt) > enrollTTL {
			delete(p.sessions, id)
		}
	}
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
