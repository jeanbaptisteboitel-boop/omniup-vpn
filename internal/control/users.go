package control

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// sessionTTL : durée de vie d'une session web utilisateur.
const sessionTTL = 7 * 24 * time.Hour

var (
	ErrInvalidInvite      = errors.New("code d'invitation invalide, déjà utilisé ou expiré")
	ErrEmailTaken         = errors.New("un compte existe déjà avec cette adresse")
	ErrBadCredentials     = errors.New("adresse ou mot de passe incorrect")
	ErrWeakPassword       = errors.New("le mot de passe doit faire au moins 8 caractères")
	ErrDeviceNotOwned     = errors.New("cette machine n'existe pas ou ne vous appartient pas")
)

// User est un compte utilisateur du VPN.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// Invite est un code d'invitation permettant de créer un compte.
type Invite struct {
	Code      string    `json:"code"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zéro : n'expire jamais
}

// WebSession est une session de l'espace utilisateur (cookie).
type WebSession struct {
	UserID  string    `json:"user_id"`
	Expires time.Time `json:"expires"`
}

// CreateInvite génère un code d'invitation (ttl = 0 : sans expiration).
func (st *Store) CreateInvite(ttl time.Duration) (*Invite, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	inv := &Invite{
		Code:      "ominv-" + randomHex(12),
		CreatedAt: time.Now().UTC(),
	}
	if ttl > 0 {
		inv.ExpiresAt = inv.CreatedAt.Add(ttl)
	}
	st.s.Invites = append(st.s.Invites, inv)
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *inv
	return &cp, nil
}

// Invites renvoie une copie de tous les codes d'invitation.
func (st *Store) Invites() []Invite {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Invite, 0, len(st.s.Invites))
	for _, inv := range st.s.Invites {
		out = append(out, *inv)
	}
	return out
}

// RegisterUser crée un compte. Si requireInvite est vrai, un code
// d'invitation valide est exigé (et consommé).
func (st *Store) RegisterUser(email, password, inviteCode string, requireInvite bool) (*User, error) {
	email = normalizeEmail(email)
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("adresse e-mail invalide")
	}
	if len(password) < 8 {
		return nil, ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if _, exists := st.s.Users[email]; exists {
		return nil, ErrEmailTaken
	}
	if requireInvite {
		var invite *Invite
		for _, inv := range st.s.Invites {
			if inv.Code == inviteCode && !inv.Used &&
				(inv.ExpiresAt.IsZero() || time.Now().Before(inv.ExpiresAt)) {
				invite = inv
				break
			}
		}
		if invite == nil {
			return nil, ErrInvalidInvite
		}
		invite.Used = true
	}

	u := &User{
		ID:           randomHex(8),
		Email:        email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now().UTC(),
	}
	if st.s.Users == nil {
		st.s.Users = map[string]*User{}
	}
	st.s.Users[email] = u
	if err := st.saveLocked(); err != nil {
		return nil, err
	}
	cp := *u
	return &cp, nil
}

// Authenticate vérifie un couple e-mail / mot de passe.
func (st *Store) Authenticate(email, password string) (*User, error) {
	email = normalizeEmail(email)
	st.mu.Lock()
	u := st.s.Users[email]
	var hash string
	if u != nil {
		hash = u.PasswordHash
	}
	st.mu.Unlock()

	// bcrypt est comparé même sans compte, pour un temps de réponse
	// indépendant de l'existence de l'adresse.
	if hash == "" {
		hash = "$2a$10$0000000000000000000000000000000000000000000000000000"
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil || u == nil {
		return nil, ErrBadCredentials
	}
	cp := *u
	return &cp, nil
}

// CreateSession ouvre une session web pour un utilisateur.
func (st *Store) CreateSession(userID string) (string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.s.Sessions == nil {
		st.s.Sessions = map[string]*WebSession{}
	}
	// Purge des sessions expirées au passage.
	for tok, sess := range st.s.Sessions {
		if time.Now().After(sess.Expires) {
			delete(st.s.Sessions, tok)
		}
	}
	token := "omsess-" + randomHex(24)
	st.s.Sessions[token] = &WebSession{UserID: userID, Expires: time.Now().Add(sessionTTL)}
	if err := st.saveLocked(); err != nil {
		return "", err
	}
	return token, nil
}

// SessionUser retrouve l'utilisateur d'une session valide.
func (st *Store) SessionUser(token string) (*User, bool) {
	if token == "" {
		return nil, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	sess, ok := st.s.Sessions[token]
	if !ok || time.Now().After(sess.Expires) {
		return nil, false
	}
	for _, u := range st.s.Users {
		if u.ID == sess.UserID {
			cp := *u
			return &cp, true
		}
	}
	return nil, false
}

// DeleteSession ferme une session web.
func (st *Store) DeleteSession(token string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.s.Sessions, token)
	_ = st.saveLocked()
}

// RemoveOwnedDevice révoque une machine si (et seulement si) elle
// appartient à owner.
func (st *Store) RemoveOwnedDevice(owner, target string) (*Device, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for pub, d := range st.s.Devices {
		if d.Owner == owner && (d.IP == target || d.Hostname == target || d.ID == target) {
			delete(st.s.Devices, pub)
			if err := st.saveLocked(); err != nil {
				return nil, err
			}
			cp := *d
			return &cp, nil
		}
	}
	return nil, ErrDeviceNotOwned
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
