// Package relay implémente le relais de secours (équivalent DERP de
// Tailscale, en UDP) : quand le perçage NAT échoue entre deux machines
// (NAT symétrique des deux côtés), leurs paquets WireGuard transitent par
// ce relais. Le relais ne voit que du chiffré : il fait suivre des trames
// opaques adressées par clé publique, sans jamais pouvoir les déchiffrer.
//
// Protocole (UDP, trames préfixées 0xC6 'O' 'M' 'N' 'R') :
//
//	REGISTER   client → relais : je revendique cette clé publique
//	CHALLENGE  relais → client : prouve-le (nonce + clé publique du relais)
//	PROOF      client → relais : HMAC du défi par le secret partagé X25519
//	ACK        relais → client : enregistrement pris en compte
//	FORWARD    client → relais : fais suivre ce paquet à telle clé publique
//	RECV       relais → client : paquet reçu de telle clé publique
//
// L'authentification repose sur un défi-réponse ECDH : les clés WireGuard
// sont des clés Curve25519 (pas de signature possible), mais seul le
// détenteur de la clé privée peut calculer X25519(priv_client, pub_relais)
// et donc produire le HMAC attendu. Un usurpateur ne peut ni s'enregistrer
// sous la clé d'autrui, ni rejouer une preuve (nonce à usage unique).
package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

const (
	headerLen = 6  // magic (5) + type (1)
	keyLen    = 32 // clé publique WireGuard brute
	nonceLen  = 16
	macLen    = sha256.Size

	TypeRegister  = 0x01
	TypeAck       = 0x02
	TypeForward   = 0x03
	TypeRecv      = 0x04
	TypeChallenge = 0x05
	TypeProof     = 0x06
)

var magic = []byte{0xC6, 'O', 'M', 'N', 'R'}

// EndpointPrefix préfixe les endpoints relais dans la configuration
// WireGuard ("relay:<clé publique base64>").
const EndpointPrefix = "relay:"

// EndpointString encode l'endpoint relais d'un pair.
func EndpointString(peerPublicKeyB64 string) string {
	return EndpointPrefix + peerPublicKeyB64
}

// IsFrame reconnaît une trame du protocole relais.
func IsFrame(b []byte) bool {
	return len(b) >= headerLen && b[0] == 0xC6 && bytes.Equal(b[1:5], magic[1:5])
}

// FrameType renvoie le type d'une trame (IsFrame doit être vrai).
func FrameType(b []byte) byte { return b[5] }

// BuildRegister encode une trame REGISTER.
func BuildRegister(selfKey [keyLen]byte) []byte {
	b := make([]byte, headerLen+keyLen)
	copy(b, magic)
	b[5] = TypeRegister
	copy(b[headerLen:], selfKey[:])
	return b
}

// BuildAck encode une trame ACK.
func BuildAck() []byte {
	b := make([]byte, headerLen)
	copy(b, magic)
	b[5] = TypeAck
	return b
}

// BuildForward encode une trame FORWARD vers dstKey.
func BuildForward(dstKey [keyLen]byte, payload []byte) []byte {
	b := make([]byte, headerLen+keyLen+len(payload))
	copy(b, magic)
	b[5] = TypeForward
	copy(b[headerLen:], dstKey[:])
	copy(b[headerLen+keyLen:], payload)
	return b
}

// BuildRecv encode une trame RECV depuis srcKey.
func BuildRecv(srcKey [keyLen]byte, payload []byte) []byte {
	b := make([]byte, headerLen+keyLen+len(payload))
	copy(b, magic)
	b[5] = TypeRecv
	copy(b[headerLen:], srcKey[:])
	copy(b[headerLen+keyLen:], payload)
	return b
}

// ParseKeyed extrait la clé et la charge utile d'une trame REGISTER,
// FORWARD ou RECV.
func ParseKeyed(b []byte) (key [keyLen]byte, payload []byte, ok bool) {
	if len(b) < headerLen+keyLen {
		return key, nil, false
	}
	copy(key[:], b[headerLen:headerLen+keyLen])
	return key, b[headerLen+keyLen:], true
}

// BuildChallenge encode une trame CHALLENGE (clé publique du relais + nonce).
func BuildChallenge(relayPub [keyLen]byte, nonce [nonceLen]byte) []byte {
	b := make([]byte, headerLen+keyLen+nonceLen)
	copy(b, magic)
	b[5] = TypeChallenge
	copy(b[headerLen:], relayPub[:])
	copy(b[headerLen+keyLen:], nonce[:])
	return b
}

// ParseChallenge décode une trame CHALLENGE.
func ParseChallenge(b []byte) (relayPub [keyLen]byte, nonce [nonceLen]byte, ok bool) {
	if len(b) != headerLen+keyLen+nonceLen {
		return relayPub, nonce, false
	}
	copy(relayPub[:], b[headerLen:])
	copy(nonce[:], b[headerLen+keyLen:])
	return relayPub, nonce, true
}

// BuildProof encode une trame PROOF pour le défi (relayPub, nonce), signée
// par la clé privée du client.
func BuildProof(clientPriv, relayPub [keyLen]byte, nonce [nonceLen]byte) ([]byte, error) {
	clientPub, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	mac, err := proofMAC(clientPriv[:], relayPub[:], clientPub, nonce)
	if err != nil {
		return nil, err
	}
	b := make([]byte, headerLen+keyLen+nonceLen+macLen)
	copy(b, magic)
	b[5] = TypeProof
	copy(b[headerLen:], clientPub)
	copy(b[headerLen+keyLen:], nonce[:])
	copy(b[headerLen+keyLen+nonceLen:], mac)
	return b, nil
}

// ParseProof décode une trame PROOF.
func ParseProof(b []byte) (clientPub [keyLen]byte, nonce [nonceLen]byte, mac []byte, ok bool) {
	if len(b) != headerLen+keyLen+nonceLen+macLen {
		return clientPub, nonce, nil, false
	}
	copy(clientPub[:], b[headerLen:])
	copy(nonce[:], b[headerLen+keyLen:])
	return clientPub, nonce, b[headerLen+keyLen+nonceLen:], true
}

// VerifyProof vérifie, côté relais, qu'une preuve correspond bien à la clé
// publique revendiquée et au nonce du défi.
func VerifyProof(relayPriv [keyLen]byte, clientPub [keyLen]byte, nonce [nonceLen]byte, mac []byte) bool {
	expected, err := proofMAC(relayPriv[:], clientPub[:], clientPub[:], nonce)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, mac)
}

// proofMAC calcule HMAC-SHA256(X25519(priv, pub), nonce || clientPub) :
// le secret partagé est identique des deux côtés (ECDH), le message lie la
// preuve à la clé revendiquée.
func proofMAC(priv, pub, clientPub []byte, nonce [nonceLen]byte) ([]byte, error) {
	shared, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, shared)
	h.Write(nonce[:])
	h.Write(clientPub)
	return h.Sum(nil), nil
}

// KeyToB64 encode une clé brute en base64 (format WireGuard usuel).
func KeyToB64(k [keyLen]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// KeyFromB64 décode une clé base64 en clé brute.
func KeyFromB64(s string) (k [keyLen]byte, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != keyLen {
		return k, false
	}
	copy(k[:], raw)
	return k, true
}
