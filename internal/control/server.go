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
}

func NewServer(store *Store) *Server {
	return &Server{store: store}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/poll", s.requireDevice(s.handlePoll))
	mux.HandleFunc("POST /api/v1/authkeys", s.requireAdmin(s.handleCreateAuthKey))
	mux.HandleFunc("GET /api/v1/devices", s.requireAdmin(s.handleListDevices))
	mux.HandleFunc("GET /api/v1/acl", s.requireAdmin(s.handleGetACL))
	mux.HandleFunc("PUT /api/v1/acl", s.requireAdmin(s.handleSetACL))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
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
		CIDR:        NetworkCIDR,
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
	if err := s.store.TouchDevice(self.PublicKey, endpoint); err != nil {
		log.Printf("poll: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}

	// La carte est filtrée par la politique d'accès : une machine ne
	// connaît que les pairs avec lesquels un échange est autorisé.
	acl := s.store.ACL()
	now := time.Now()
	nm := types.NetMap{Self: peerView(self, now)}
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
	k, err := s.store.CreateAuthKey(reusable)
	if err != nil {
		log.Printf("authkeys: %v", err)
		writeError(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, types.AuthKeyResponse{Key: k.Key, Reusable: k.Reusable})
}

func (s *Server) handleListDevices(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	peers := []types.Peer{}
	for _, d := range s.store.Devices() {
		peers = append(peers, peerView(d, now))
	}
	writeJSON(w, http.StatusOK, peers)
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
		Endpoint:  d.Endpoint,
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, types.ErrorResponse{Error: msg})
}
