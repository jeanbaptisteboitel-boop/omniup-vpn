package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DefaultCIDR est la plage d'adresses par défaut du réseau overlay
// (CGNAT, comme Tailscale). Configurable jusqu'à 100.64.0.0/10 via
// « omni-server serve --cidr », figée au premier démarrage.
const DefaultCIDR = "100.64.0.0/24"

// OnlineThreshold : une machine est considérée en ligne si elle a poll
// le serveur dans cet intervalle (l'agent poll toutes les 10 s).
const OnlineThreshold = 35 * time.Second

var (
	ErrInvalidAuthKey = errors.New("clé d'authentification invalide ou déjà utilisée")
	ErrIPExhausted    = errors.New("plage d'adresses IP épuisée")
)

// TokenRotateAfter : âge au-delà duquel le jeton d'une machine est
// renouvelé au poll suivant (variable pour les tests).
var TokenRotateAfter = 24 * time.Hour

// tokenGrace : durée pendant laquelle l'ancien jeton reste accepté après
// une rotation, au cas où la réponse portant le nouveau jeton se perde.
const tokenGrace = time.Hour

// Device est une machine enregistrée sur le réseau.
type Device struct {
	ID             string    `json:"id"`
	Hostname       string    `json:"hostname"`
	Owner          string    `json:"owner,omitempty"` // e-mail SSO, vide si enrôlée par clé
	PublicKey      string    `json:"public_key"`
	Token          string    `json:"token"`
	TokenIssuedAt  time.Time `json:"token_issued_at,omitempty"`
	PrevToken      string    `json:"prev_token,omitempty"`
	PrevTokenUntil time.Time `json:"prev_token_until,omitempty"`
	IP             string    `json:"ip"`
	Endpoint       string    `json:"endpoint,omitempty"`  // observé par le serveur
	Endpoints      []string  `json:"endpoints,omitempty"` // candidats rapportés par l'agent
	CreatedAt      time.Time `json:"created_at"`
	LastSeen       time.Time `json:"last_seen"`
}

// AuthKey est une clé de pré-authentification permettant d'enrôler une machine.
type AuthKey struct {
	Key       string    `json:"key"`
	Owner     string    `json:"owner,omitempty"` // les machines enrôlées lui sont rattachées
	Reusable  bool      `json:"reusable"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zéro : n'expire jamais
}

type stateFile struct {
	AdminKey string                 `json:"admin_key"`
	CIDR     string                 `json:"cidr,omitempty"`
	AuthKeys []*AuthKey             `json:"auth_keys"`
	Devices  map[string]*Device     `json:"devices"` // indexées par clé publique
	ACL      *ACLPolicy             `json:"acl,omitempty"`
	Users    map[string]*User       `json:"users,omitempty"`    // indexés par e-mail
	Invites  []*Invite              `json:"invites,omitempty"`
	Sessions map[string]*WebSession `json:"sessions,omitempty"` // indexées par jeton
}

// Store conserve l'état du serveur (machines, clés) et le persiste en JSON.
type Store struct {
	mu   sync.Mutex
	path string
	s    *stateFile
}

// OpenStore charge l'état depuis path, ou initialise un état vide avec la
// plage DefaultCIDR. Renvoie aussi true si la clé admin vient d'être créée.
func OpenStore(path string) (*Store, bool, error) {
	return OpenStoreCIDR(path, DefaultCIDR)
}

// OpenStoreCIDR ouvre l'état en fixant la plage d'adresses au premier
// démarrage. Sur un état existant, la plage enregistrée fait foi (changer
// de plage implique de ré-enrôler les machines).
func OpenStoreCIDR(path, cidr string) (*Store, bool, error) {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil, false, fmt.Errorf("cidr invalide %q: %w", cidr, err)
	}
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
	}
	if st.s.CIDR == "" {
		st.s.CIDR = cidr
	}
	if created {
		if err := st.saveLocked(); err != nil {
			return nil, false, err
		}
	}
	return st, created, nil
}

// CIDR renvoie la plage d'adresses du réseau overlay.
func (st *Store) CIDR() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s.CIDR
}

// AdminKey renvoie la clé d'administration du serveur.
func (st *Store) AdminKey() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s.AdminKey
}

// CreateAuthKey génère une nouvelle clé de pré-authentification.
// ttl = 0 : la clé n'expire jamais.
func (st *Store) CreateAuthKey(reusable bool, ttl time.Duration) (*AuthKey, error) {
	return st.CreateAuthKeyFor("", reusable, ttl)
}

// CreateAuthKeyFor génère une clé de pré-authentification rattachée à un
// utilisateur : les machines enrôlées avec elle lui appartiendront.
func (st *Store) CreateAuthKeyFor(owner string, reusable bool, ttl time.Duration) (*AuthKey, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := &AuthKey{
		Key:       "omkey-" + randomHex(24),
		Owner:     owner,
		Reusable:  reusable,
		CreatedAt: time.Now().UTC(),
	}
	if ttl > 0 {
		k.ExpiresAt = k.CreatedAt.Add(ttl)
	}
	st.s.AuthKeys = append(st.s.AuthKeys, k)
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *k
	return &cp, nil
}

// AuthKeys renvoie une copie de toutes les clés d'enrôlement.
func (st *Store) AuthKeys() []AuthKey {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]AuthKey, 0, len(st.s.AuthKeys))
	for _, k := range st.s.AuthKeys {
		out = append(out, *k)
	}
	return out
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
		if k.Key == authKey && (k.Reusable || !k.Used) &&
			(k.ExpiresAt.IsZero() || time.Now().Before(k.ExpiresAt)) {
			key = k
			break
		}
	}
	if key == nil {
		return nil, ErrInvalidAuthKey
	}

	d, err := st.createDeviceLocked(hostname, publicKey, key.Owner)
	if err != nil {
		return nil, err
	}
	key.Used = true
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *d
	return &cp, nil
}

// RegisterDeviceSSO enrôle une machine au nom d'un utilisateur authentifié
// par le fournisseur d'identité (pas de clé d'enrôlement à consommer).
// Idempotent pour une clé publique déjà connue.
func (st *Store) RegisterDeviceSSO(hostname, publicKey, owner string) (*Device, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if d, ok := st.s.Devices[publicKey]; ok {
		changed := false
		if hostname != "" && d.Hostname != hostname {
			d.Hostname = hostname
			changed = true
		}
		if owner != "" && d.Owner != owner {
			d.Owner = owner
			changed = true
		}
		if changed {
			if err := st.saveLocked(); err != nil {
				return nil, err
			}
		}
		cp := *d
		return &cp, nil
	}

	d, err := st.createDeviceLocked(hostname, publicKey, owner)
	if err != nil {
		return nil, err
	}
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *d
	return &cp, nil
}

// createDeviceLocked alloue une IP et crée la machine (sans sauvegarder).
func (st *Store) createDeviceLocked(hostname, publicKey, owner string) (*Device, error) {
	ip, err := st.allocateIPLocked()
	if err != nil {
		return nil, err
	}
	d := &Device{
		ID:            randomHex(8),
		Hostname:      hostname,
		Owner:         owner,
		PublicKey:     publicKey,
		Token:         "omtok-" + randomHex(24),
		TokenIssuedAt: time.Now().UTC(),
		IP:            ip,
		CreatedAt:     time.Now().UTC(),
	}
	st.s.Devices[publicKey] = d
	return d, nil
}

// DeviceByToken retrouve une machine par son jeton d'API (le jeton
// précédent reste accepté pendant la période de grâce après rotation).
func (st *Store) DeviceByToken(token string) (*Device, bool) {
	if token == "" {
		return nil, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.s.Devices {
		if d.Token == token ||
			(d.PrevToken == token && time.Now().Before(d.PrevTokenUntil)) {
			cp := *d
			return &cp, true
		}
	}
	return nil, false
}

// RotateTokenIfDue renouvelle le jeton d'une machine s'il est trop ancien.
// Renvoie le nouveau jeton, ou "" si aucune rotation n'était due. L'ancien
// jeton reste valide pendant tokenGrace pour absorber une réponse perdue.
func (st *Store) RotateTokenIfDue(publicKey string) (string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[publicKey]
	if !ok {
		return "", errors.New("machine inconnue")
	}
	if time.Since(d.TokenIssuedAt) < TokenRotateAfter {
		return "", nil
	}
	now := time.Now().UTC()
	d.PrevToken = d.Token
	d.PrevTokenUntil = now.Add(tokenGrace)
	d.Token = "omtok-" + randomHex(24)
	d.TokenIssuedAt = now
	if err := st.saveLocked(); err != nil {
		return "", err
	}
	return d.Token, nil
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

// allocateIPLocked attribue la première adresse libre de la plage
// (adresses de réseau et de broadcast exclues).
func (st *Store) allocateIPLocked() (string, error) {
	prefix, err := netip.ParsePrefix(st.s.CIDR)
	if err != nil {
		return "", fmt.Errorf("cidr de l'état invalide %q: %w", st.s.CIDR, err)
	}
	prefix = prefix.Masked()
	used := make(map[string]bool, len(st.s.Devices))
	for _, d := range st.s.Devices {
		used[d.IP] = true
	}
	for a := prefix.Addr().Next(); prefix.Contains(a) && prefix.Contains(a.Next()); a = a.Next() {
		if !used[a.String()] {
			return a.String(), nil
		}
	}
	return "", ErrIPExhausted
}

// RemoveDevice révoque une machine désignée par son IP, son nom ou son ID.
// La machine disparaît des cartes du réseau au prochain poll des agents et
// son jeton cesse d'être valide.
func (st *Store) RemoveDevice(target string) (*Device, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for pub, d := range st.s.Devices {
		if d.IP == target || d.Hostname == target || d.ID == target {
			delete(st.s.Devices, pub)
			if err := st.saveLocked(); err != nil {
				return nil, err
			}
			cp := *d
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("aucune machine ne correspond à %q", target)
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
