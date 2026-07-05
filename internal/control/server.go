package control

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Server expose l'API HTTP du plan de contrôle.
//
// Endpoints machine :
//   POST /api/v1/register  — enrôlement avec une clé d'authentification
//   POST /api/v1/poll      — heartbeat + récupération de la carte du réseau
//
// Endpoints admin (Bearer <clé admin>) :
//   POST /api/v1/authkeys  — création d'une clé de pré-authentification
//   GET  /api/v1/devices   — liste des machines
type Server struct {
	store *Store
	oidc  *oidcProvider // nil : enrôlement SSO désactivé
}

func NewServer(store *Store) *Server {
	return &Server{store: store}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/poll", s.requireDevice(s.handlePoll))
	mux.HandleFunc("POST /api/v1/authkeys", s.requireAdmin(s.handleCreateAuthKey))
	mux.HandleFunc("GET /api/v1/authkeys", s.requireAdmin(s.handleListAuthKeys))
	mux.HandleFunc("GET /api/v1/devices", s.requireAdmin(s.handleListDevices))
	mux.HandleFunc("DELETE /api/v1/devices/{target}", s.requireAdmin(s.handleRevokeDevice))
	mux.HandleFunc("GET /api/v1/acl", s.requireAdmin(s.handleGetACL))
	mux.HandleFunc("PUT /api/v1/acl", s.requireAdmin(s.handleSetACL))
	mux.HandleFunc("GET /api/v1/info", s.requireAdmin(s.handleInfo))
	mux.HandleFunc("POST /api/v1/enroll/start", s.handleEnrollStart)
	mux.HandleFunc("GET /api/v1/enroll/wait", s.handleEnrollWait)
	mux.HandleFunc("GET /enroll/{id}", s.handleEnrollRedirect)
	mux.HandleFunc("GET /oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	registerWebUI(mux)
	return mux
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req types.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	d, err := s.store.RegisterDevice(req.AuthKey, req.Hostname, req.PublicKey)
	switch {
	case errors.Is(err, ErrInvalidAuthKey):
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		log.Printf("register: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}

	log.Printf("machine enregistrée: %s (%s)", d.Hostname, d.IP)
	writeJSON(w, http.StatusOK, types.RegisterResponse{
		DeviceID:    d.ID,
		DeviceToken: d.Token,
		IP:          d.IP,
		CIDR:        s.store.CIDR(),
	})
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request, self Device) {
	var req types.PollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "corps JSON invalide")
		return
	}

	// L'endpoint public de la machine est déduit de l'IP source de la
	// requête HTTP et du port d'écoute WireGuard déclaré par l'agent.
	// (Limite connue : NAT symétrique — voir la feuille de route, STUN.)
	endpoint := ""
	if req.ListenPort > 0 {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			endpoint = net.JoinHostPort(host, strconv.Itoa(req.ListenPort))
		}
	}
	if err := s.store.TouchDevice(self.PublicKey, endpoint, req.Endpoints); err != nil {
		log.Printf("poll: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}

	// Rotation périodique du jeton : le nouveau jeton part dans la
	// réponse, l'ancien reste toléré le temps d'une période de grâce.
	newToken, err := s.store.RotateTokenIfDue(self.PublicKey)
	if err != nil {
		log.Printf("poll: rotation du jeton: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	if newToken != "" {
		log.Printf("jeton renouvelé pour %s (%s)", self.Hostname, self.IP)
	}

	// La carte est filtrée par la politique d'accès : une machine ne
	// connaît que les pairs avec lesquels un échange est autorisé.
	acl := s.store.ACL()
	now := time.Now()
	nm := types.NetMap{Self: peerView(self, now), NewToken: newToken}
	nm.Self.Online = true
	for _, d := range s.store.Devices() {
		if d.PublicKey == self.PublicKey {
			nm.Self = peerView(d, now)
			continue
		}
		if !acl.Visible(self, d) {
			continue
		}
		nm.Peers = append(nm.Peers, peerView(d, now))
	}
	writeJSON(w, http.StatusOK, nm)
}

func (s *Server) handleCreateAuthKey(w http.ResponseWriter, r *http.Request) {
	reusable := r.URL.Query().Get("reusable") == "true"
	ttl := 24 * time.Hour // défaut : une clé d'enrôlement vit un jour
	if v := r.URL.Query().Get("ttl"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "ttl invalide (ex: 24h, 30m, 0 pour sans expiration)")
			return
		}
		ttl = parsed
	}
	k, err := s.store.CreateAuthKey(reusable, ttl)
	if err != nil {
		log.Printf("authkeys: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, types.AuthKeyResponse{Key: k.Key, Reusable: k.Reusable, ExpiresAt: k.ExpiresAt})
}

func (s *Server) handleListDevices(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	peers := []types.Peer{}
	for _, d := range s.store.Devices() {
		peers = append(peers, peerView(d, now))
	}
	writeJSON(w, http.StatusOK, peers)
}

func (s *Server) handleListAuthKeys(w http.ResponseWriter, _ *http.Request) {
	keys := []types.AuthKeyInfo{}
	for _, k := range s.store.AuthKeys() {
		keys = append(keys, types.AuthKeyInfo{
			KeyMasked: maskKey(k.Key),
			Reusable:  k.Reusable,
			Used:      k.Used,
			CreatedAt: k.CreatedAt,
			ExpiresAt: k.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	info := types.InfoResponse{CIDR: s.store.CIDR()}
	for _, d := range s.store.Devices() {
		info.DeviceCount++
		if !d.LastSeen.IsZero() && now.Sub(d.LastSeen) < OnlineThreshold {
			info.OnlineCount++
		}
	}
	writeJSON(w, http.StatusOK, info)
}

// maskKey ne laisse visible que la fin d'une clé (identification sans
// divulgation : la valeur complète n'est montrée qu'à la création).
func maskKey(key string) string {
	if len(key) <= 10 {
		return key
	}
	return key[:6] + "…" + key[len(key)-6:]
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.RemoveDevice(r.PathValue("target"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	log.Printf("machine révoquée: %s (%s)", d.Hostname, d.IP)
	writeJSON(w, http.StatusOK, peerView(*d, time.Now()))
}

func (s *Server) handleGetACL(w http.ResponseWriter, _ *http.Request) {
	acl := s.store.ACL()
	if acl == nil {
		acl = &ACLPolicy{}
	}
	writeJSON(w, http.StatusOK, acl)
}

func (s *Server) handleSetACL(w http.ResponseWriter, r *http.Request) {
	var p ACLPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "corps JSON invalide")
		return
	}
	if err := p.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SetACL(&p); err != nil {
		log.Printf("acl: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	log.Printf("politique d'accès mise à jour (%d règle(s))", len(p.Rules))
	writeJSON(w, http.StatusOK, &p)
}

func peerView(d Device, now time.Time) types.Peer {
	return types.Peer{
		Hostname:  d.Hostname,
		PublicKey: d.PublicKey,
		IP:        d.IP,
		Owner:     d.Owner,
		Endpoint:  d.Endpoint,
		Endpoints: append([]string(nil), d.Endpoints...),
		LastSeen:  d.LastSeen,
		Online:    !d.LastSeen.IsZero() && now.Sub(d.LastSeen) < OnlineThreshold,
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.store.AdminKey())) != 1 {
			writeError(w, http.StatusUnauthorized, "clé admin invalide")
			return
		}
		next(w, r)
	}
}

func (s *Server) requireDevice(next func(http.ResponseWriter, *http.Request, Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := s.store.DeviceByToken(bearerToken(r))
		if !ok {
			writeError(w, http.StatusUnauthorized, "jeton machine invalide")
			return
		}
		next(w, r, *d)
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, types.ErrorResponse{Error: msg})
}
