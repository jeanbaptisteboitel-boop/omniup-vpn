// Package types définit les structures échangées entre l'agent (omnid)
// et le serveur de coordination (omni-server).
package types

import "time"

// RegisterRequest est envoyée par un agent pour enregistrer une machine
// sur le réseau à l'aide d'une clé d'authentification.
type RegisterRequest struct {
	AuthKey   string `json:"auth_key"`
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"` // clé publique WireGuard (base64)
}

// RegisterResponse contient l'identité attribuée à la machine.
type RegisterResponse struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"` // jeton pour les appels suivants
	IP          string `json:"ip"`           // ex: 100.64.0.1
	CIDR        string `json:"cidr"`         // ex: 100.64.0.0/24
}

// PollRequest est envoyée périodiquement par l'agent : elle signale le port
// d'écoute WireGuard et les endpoints candidats découverts (STUN, adresses
// locales), et récupère la carte du réseau en retour.
type PollRequest struct {
	ListenPort int      `json:"listen_port"`
	Endpoints  []string `json:"endpoints,omitempty"`
}

// Peer décrit une machine du réseau telle que vue par le serveur.
type Peer struct {
	Hostname  string    `json:"hostname"`
	PublicKey string    `json:"public_key"`
	IP        string    `json:"ip"`
	Owner     string    `json:"owner,omitempty"`     // e-mail SSO, vide si enrôlée par clé
	Endpoint  string    `json:"endpoint,omitempty"`  // observé par le serveur
	Endpoints []string  `json:"endpoints,omitempty"` // candidats rapportés par l'agent
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
}

// EnrollStartRequest ouvre une session d'enrôlement SSO : l'agent fournit
// son identité WireGuard, l'utilisateur s'authentifie dans un navigateur.
type EnrollStartRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}

// EnrollStartResponse contient l'URL à ouvrir dans un navigateur.
type EnrollStartResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
}

// NetMap est la carte du réseau distribuée à chaque agent.
type NetMap struct {
	Self  Peer   `json:"self"`
	Peers []Peer `json:"peers"`
	// NewToken est renseigné quand le serveur renouvelle le jeton de la
	// machine (rotation périodique) : l'agent doit le persister et
	// l'utiliser dès l'appel suivant.
	NewToken string `json:"new_token,omitempty"`
}

// AuthKeyResponse est renvoyée lors de la création d'une clé d'authentification.
type AuthKeyResponse struct {
	Key       string    `json:"key"`
	Reusable  bool      `json:"reusable"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// AuthKeyInfo décrit une clé d'enrôlement existante (clé masquée : la
// valeur complète n'est montrée qu'à la création).
type AuthKeyInfo struct {
	KeyMasked string    `json:"key_masked"`
	Reusable  bool      `json:"reusable"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// InfoResponse résume l'état du réseau pour la console d'administration.
type InfoResponse struct {
	CIDR        string `json:"cidr"`
	DeviceCount int    `json:"device_count"`
	OnlineCount int    `json:"online_count"`
}

// UserRegisterRequest crée un compte utilisateur sur le portail.
type UserRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Invite   string `json:"invite,omitempty"`
}

// UserLoginRequest ouvre une session sur le portail.
type UserLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserProfile est le profil renvoyé à un utilisateur connecté.
type UserProfile struct {
	Email    string `json:"email"`
	Machines []Peer `json:"machines"`
}

// InviteResponse est renvoyée à la création d'un code d'invitation.
type InviteResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// InviteInfo décrit un code d'invitation existant (masqué).
type InviteInfo struct {
	CodeMasked string    `json:"code_masked"`
	Used       bool      `json:"used"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
}

// ErrorResponse est le format d'erreur JSON de l'API.
type ErrorResponse struct {
	Error string `json:"error"`
}
