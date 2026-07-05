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
// d'écoute WireGuard et récupère la carte du réseau en retour.
type PollRequest struct {
	ListenPort int `json:"listen_port"`
}

// Peer décrit une machine du réseau telle que vue par le serveur.
type Peer struct {
	Hostname  string    `json:"hostname"`
	PublicKey string    `json:"public_key"`
	IP        string    `json:"ip"`
	Endpoint  string    `json:"endpoint,omitempty"` // "ip_publique:port" si connu
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
}

// NetMap est la carte du réseau distribuée à chaque agent.
type NetMap struct {
	Self  Peer   `json:"self"`
	Peers []Peer `json:"peers"`
}

// AuthKeyResponse est renvoyée lors de la création d'une clé d'authentification.
type AuthKeyResponse struct {
	Key      string `json:"key"`
	Reusable bool   `json:"reusable"`
}

// ErrorResponse est le format d'erreur JSON de l'API.
type ErrorResponse struct {
	Error string `json:"error"`
}
