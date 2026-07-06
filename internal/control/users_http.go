package control

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

const sessionCookie = "omniup_session"

// registerUserRoutes branche l'espace utilisateur sur le mux.
func (s *Server) registerUserRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users/config", s.handleUserConfig)
	mux.HandleFunc("POST /api/v1/users/register", s.handleUserRegister)
	mux.HandleFunc("POST /api/v1/users/login", s.handleUserLogin)
	mux.HandleFunc("POST /api/v1/users/logout", s.handleUserLogout)
	mux.HandleFunc("GET /api/v1/users/me", s.requireUser(s.handleUserMe))
	mux.HandleFunc("POST /api/v1/users/authkeys", s.requireUser(s.handleUserAuthKey))
	mux.HandleFunc("DELETE /api/v1/users/devices/{target}", s.requireUser(s.handleUserRevoke))
	mux.HandleFunc("POST /api/v1/invites", s.requireAdmin(s.handleCreateInvite))
	mux.HandleFunc("GET /api/v1/invites", s.requireAdmin(s.handleListInvites))
}

// handleUserConfig indique au portail si l'inscription exige une invitation.
func (s *Server) handleUserConfig(w http.ResponseWriter, _ *http.Request) {
	mode := "invite"
	if s.openRegistration {
		mode = "open"
	}
	writeJSON(w, http.StatusOK, map[string]string{"registration": mode})
}

func (s *Server) handleUserRegister(w http.ResponseWriter, r *http.Request) {
	var req types.UserRegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "corps JSON invalide")
		return
	}
	u, err := s.store.RegisterUser(req.Email, req.Password, req.Invite, !s.openRegistration)
	switch {
	case errors.Is(err, ErrInvalidInvite), errors.Is(err, ErrWeakPassword):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, ErrEmailTaken):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("compte utilisateur créé: %s", u.Email)
	s.openSession(w, r, u)
}

func (s *Server) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	var req types.UserLoginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "corps JSON invalide")
		return
	}
	u, err := s.store.Authenticate(req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrBadCredentials.Error())
		return
	}
	s.openSession(w, r, u)
}

// openSession pose le cookie de session et renvoie le profil.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request, u *User) {
	token, err := s.store.CreateSession(u.ID)
	if err != nil {
		log.Printf("session: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"email": u.Email})
}

func (s *Server) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleUserMe renvoie le profil et les machines de l'utilisateur.
func (s *Server) handleUserMe(w http.ResponseWriter, _ *http.Request, u User) {
	now := time.Now()
	machines := []types.Peer{}
	for _, d := range s.store.Devices() {
		if d.Owner == u.Email {
			machines = append(machines, peerView(d, now))
		}
	}
	writeJSON(w, http.StatusOK, types.UserProfile{Email: u.Email, Machines: machines})
}

// handleUserAuthKey crée une clé d'enrôlement rattachée à l'utilisateur.
func (s *Server) handleUserAuthKey(w http.ResponseWriter, r *http.Request, u User) {
	reusable := r.URL.Query().Get("reusable") == "true"
	k, err := s.store.CreateAuthKeyFor(u.Email, reusable, 24*time.Hour)
	if err != nil {
		log.Printf("authkey utilisateur: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, types.AuthKeyResponse{Key: k.Key, Reusable: k.Reusable, ExpiresAt: k.ExpiresAt})
}

// handleUserRevoke révoque une machine de l'utilisateur (et d'elle seule).
func (s *Server) handleUserRevoke(w http.ResponseWriter, r *http.Request, u User) {
	d, err := s.store.RemoveOwnedDevice(u.Email, r.PathValue("target"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	log.Printf("machine révoquée par %s: %s (%s)", u.Email, d.Hostname, d.IP)
	writeJSON(w, http.StatusOK, peerView(*d, time.Now()))
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	ttl := 7 * 24 * time.Hour // défaut : une invitation vit une semaine
	if v := r.URL.Query().Get("ttl"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "ttl invalide (ex: 168h, 0 pour sans expiration)")
			return
		}
		ttl = parsed
	}
	inv, err := s.store.CreateInvite(ttl)
	if err != nil {
		log.Printf("invites: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, types.InviteResponse{Code: inv.Code, ExpiresAt: inv.ExpiresAt})
}

func (s *Server) handleListInvites(w http.ResponseWriter, _ *http.Request) {
	out := []types.InviteInfo{}
	for _, inv := range s.store.Invites() {
		out = append(out, types.InviteInfo{
			CodeMasked: maskKey(inv.Code),
			Used:       inv.Used,
			CreatedAt:  inv.CreatedAt,
			ExpiresAt:  inv.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// requireUser authentifie l'utilisateur par son cookie de session.
func (s *Server) requireUser(next func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "connexion requise")
			return
		}
		u, ok := s.store.SessionUser(c.Value)
		if !ok {
			writeError(w, http.StatusUnauthorized, "session expirée, reconnectez-vous")
			return
		}
		next(w, r, *u)
	}
}

// isHTTPS tient compte d'un reverse proxy TLS (Caddy, nginx…).
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
