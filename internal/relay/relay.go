// Package relay implémente le relais de secours (équivalent DERP de
// Tailscale, en UDP) : quand le perçage NAT échoue entre deux machines
// (NAT symétrique des deux côtés), leurs paquets WireGuard transitent par
// ce relais. Le relais ne voit que du chiffré : il fait suivre des trames
// opaques adressées par clé publique, sans jamais pouvoir les déchiffrer.
//
// Protocole (UDP, trames préfixées 0xC6 'O' 'M' 'N' 'R') :
//
//	REGISTER  client → relais : ma clé publique est joignable à mon adresse source
//	ACK       relais → client : enregistrement pris en compte
//	FORWARD   client → relais : fais suivre ce paquet à telle clé publique
//	RECV      relais → client : paquet reçu de telle clé publique
package relay

import (
	"bytes"
	"encoding/base64"
)

const (
	headerLen = 6  // magic (5) + type (1)
	keyLen    = 32 // clé publique WireGuard brute

	TypeRegister = 0x01
	TypeAck      = 0x02
	TypeForward  = 0x03
	TypeRecv     = 0x04
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
