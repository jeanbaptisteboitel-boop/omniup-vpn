package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// NetworkCIDR est la plage d'adresses du réseau overlay (CGNAT, comme Tailscale).
// MVP : un /24 ; la cible à terme est 100.64.0.0/10.
const NetworkCIDR = "100.64.0.0/24"

// OnlineThreshold : une machine est considérée en ligne si elle a poll
// le serveur dans cet intervalle (l'agent poll toutes les 10 s).
const OnlineThreshold = 35 * time.Second

var (
	ErrInvalidAuthKey = errors.New("clé d'authentification invalide ou déjà utilisée")
	ErrIPExhausted    = errors.New("plage d'adresses IP épuisée")
)

// Device est une machine enregistrée sur le réseau.
type Device struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	PublicKey string    `json:"public_key"`
	Token     string    `json:"token"`
	IP        string    `json:"ip"`
	Endpoint  string    `json:"endpoint,omitempty"`  // observé par le serveur
	Endpoints []string  `json:"endpoints,omitempty"` // candidats rapportés par l'agent
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// AuthKey est une clé de pré-authentification permettant d'enrôler une machine.
type AuthKey struct {
	Key       string    `json:"key"`
	Reusable  bool      `json:"reusable"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

type stateFile struct {
	AdminKey string             `json:"admin_key"`
	AuthKeys []*AuthKey         `json:"auth_keys"`
	Devices  map[string]*Device `json:"devices"` // indexées par clé publique
	ACL      *ACLPolicy         `json:"acl,omitempty"`
}

// Store conserve l'état du serveur (machines, clés) et le persiste en JSON.
type Store struct {
	mu   sync.Mutex
	path string
	s    *stateFile
}

// OpenStore charge l'état depuis path, ou initialise un état vide.
// Renvoie aussi true si la clé admin vient d'être créée (premier démarrage).
func OpenStore(path string) (*Store, bool, error) {
	st := &Store{path: path, s: &stateFile{Devices: map[string]*Device{}}}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, st.s); err != nil {
			return nil, false, fmt.Errorf("état corrompu %s: %w", path, err)
		}
		if st.s.Devices == nil {
			st.s.Devices = map[string]*Device{}
		}
	case os.IsNotExist(err):
		// premier démarrage
	default:
		return nil, false, err
	}

	created := false
	if st.s.AdminKey == "" {
		st.s.AdminKey = "omadmin-" + randomHex(24)
		created = true
		if err := st.saveLocked(); err != nil {
			return nil, false, err
		}
	}
	return st, created, nil
}

// AdminKey renvoie la clé d'administration du serveur.
func (st *Store) AdminKey() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s.AdminKey
}

// CreateAuthKey génère une nouvelle clé de pré-authentification.
func (st *Store) CreateAuthKey(reusable bool) (*AuthKey, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := &AuthKey{
		Key:       "omkey-" + randomHex(24),
		Reusable:  reusable,
		CreatedAt: time.Now().UTC(),
	}
	st.s.AuthKeys = append(st.s.AuthKeys, k)
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *k
	return &cp, nil
}

// RegisterDevice enrôle une machine avec une clé d'authentification valide.
// Si la clé publique est déjà connue, la machine existante est renvoyée
// (ré-enregistrement idempotent) sans consommer la clé.
func (st *Store) RegisterDevice(authKey, hostname, publicKey string) (*Device, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if d, ok := st.s.Devices[publicKey]; ok {
		if hostname != "" && d.Hostname != hostname {
			d.Hostname = hostname
			if err := st.saveLocked(); err != nil {
				return nil, err
			}
		}
		cp := *d
		return &cp, nil
	}

	var key *AuthKey
	for _, k := range st.s.AuthKeys {
		if k.Key == authKey && (k.Reusable || !k.Used) {
			key = k
			break
		}
	}
	if key == nil {
		return nil, ErrInvalidAuthKey
	}

	ip, err := st.allocateIPLocked()
	if err != nil {
		return nil, err
	}

	d := &Device{
		ID:        randomHex(8),
		Hostname:  hostname,
		PublicKey: publicKey,
		Token:     "omtok-" + randomHex(24),
		IP:        ip,
		CreatedAt: time.Now().UTC(),
	}
	key.Used = true
	st.s.Devices[publicKey] = d
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *d
	return &cp, nil
}

// DeviceByToken retrouve une machine par son jeton d'API.
func (st *Store) DeviceByToken(token string) (*Device, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.s.Devices {
		if d.Token == token {
			cp := *d
			return &cp, true
		}
	}
	return nil, false
}

// TouchDevice met à jour la date de dernière activité, l'endpoint observé
// par le serveur et les candidats rapportés par l'agent.
func (st *Store) TouchDevice(publicKey, endpoint string, reported []string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[publicKey]
	if !ok {
		return errors.New("machine inconnue")
	}
	d.LastSeen = time.Now().UTC()
	if endpoint != "" {
		d.Endpoint = endpoint
	}
	if reported != nil {
		d.Endpoints = append([]string(nil), reported...)
	}
	return st.saveLocked()
}

// Devices renvoie une copie de toutes les machines, triée par IP.
func (st *Store) Devices() []Device {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Device, 0, len(st.s.Devices))
	for _, d := range st.s.Devices {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// ACL renvoie une copie de la politique d'accès courante (nil = tout autorisé).
func (st *Store) ACL() *ACLPolicy {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s.ACL.clone()
}

// SetACL remplace la politique d'accès.
func (st *Store) SetACL(p *ACLPolicy) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.s.ACL = p.clone()
	return st.saveLocked()
}

// allocateIPLocked attribue la première adresse libre de la plage.
func (st *Store) allocateIPLocked() (string, error) {
	used := make(map[string]bool, len(st.s.Devices))
	for _, d := range st.s.Devices {
		used[d.IP] = true
	}
	for host := 1; host < 255; host++ {
		ip := fmt.Sprintf("100.64.0.%d", host)
		if !used[ip] {
			return ip, nil
		}
	}
	return "", ErrIPExhausted
}

// saveLocked persiste l'état de façon atomique (fichier temporaire + rename).
func (st *Store) saveLocked() error {
	data, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(st.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), st.path)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // l'absence d'entropie système est irrécupérable
	}
	return hex.EncodeToString(b)
}
