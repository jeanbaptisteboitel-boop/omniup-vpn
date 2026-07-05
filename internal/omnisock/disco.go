package omnisock

import (
	"bytes"
	"crypto/rand"
)

// Le protocole « disco » sert au perçage NAT : des sondes ping/pong
// échangées sur la socket WireGuard elle-même. Envoyer un ping vers un
// candidat ouvre le mapping NAT local vers ce pair ; recevoir un pong
// prouve que le chemin fonctionne dans les deux sens. Les sondes ne
// transportent aucune donnée : le trafic réel reste authentifié et
// chiffré par WireGuard.
//
// Format (18 octets) : 0xC5 'O' 'M' 'N' 'I' <type> <txid ×12>
// Le premier octet 0xC5 ne peut pas être confondu avec un message
// WireGuard (types 1 à 4) ni avec STUN (deux bits de poids fort nuls).

const discoLen = 18

var discoMagic = []byte{0xC5, 'O', 'M', 'N', 'I'}

const (
	discoPing = 0x01
	discoPong = 0x02
)

// DiscoTxID identifie une sonde disco.
type DiscoTxID [12]byte

// NewDiscoTxID génère un identifiant de sonde aléatoire.
func NewDiscoTxID() DiscoTxID {
	var id DiscoTxID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}

func isDisco(b []byte) bool {
	return len(b) == discoLen && bytes.Equal(b[:5], discoMagic)
}

func encodeDisco(msgType byte, id DiscoTxID) []byte {
	b := make([]byte, discoLen)
	copy(b, discoMagic)
	b[5] = msgType
	copy(b[6:], id[:])
	return b
}

func decodeDisco(b []byte) (msgType byte, id DiscoTxID) {
	msgType = b[5]
	copy(id[:], b[6:])
	return
}
