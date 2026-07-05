// Package stun implémente le strict nécessaire de STUN (RFC 5389) pour la
// découverte d'endpoint public : requêtes/réponses Binding avec l'attribut
// XOR-MAPPED-ADDRESS. Le serveur est embarqué dans omni-server ; le client
// est utilisé par l'agent à travers sa socket WireGuard, afin de découvrir
// le mapping NAT du port réellement utilisé par les tunnels.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	// MagicCookie est la constante RFC 5389 (octets 4 à 8 de tout message).
	MagicCookie = 0x2112A442

	headerLen = 20

	typeBindingRequest  = 0x0001
	typeBindingResponse = 0x0101

	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020

	familyIPv4 = 0x01
	familyIPv6 = 0x02
)

// TxID identifie une transaction STUN.
type TxID [12]byte

// NewTxID génère un identifiant de transaction aléatoire.
func NewTxID() TxID {
	var id TxID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}

// IsMessage reconnaît un message STUN (deux bits de poids fort nuls
// + magic cookie). Sert au démultiplexage sur la socket WireGuard.
func IsMessage(b []byte) bool {
	return len(b) >= headerLen &&
		b[0]&0xC0 == 0 &&
		binary.BigEndian.Uint32(b[4:8]) == MagicCookie
}

// IsBindingResponse reconnaît une réponse Binding succès.
func IsBindingResponse(b []byte) bool {
	return IsMessage(b) && binary.BigEndian.Uint16(b[0:2]) == typeBindingResponse
}

// BuildBindingRequest encode une requête Binding.
func BuildBindingRequest(id TxID) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], typeBindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 0) // pas d'attribut
	binary.BigEndian.PutUint32(b[4:8], MagicCookie)
	copy(b[8:20], id[:])
	return b
}

// BuildBindingResponse encode une réponse Binding portant l'adresse
// observée addr, en XOR-MAPPED-ADDRESS.
func BuildBindingResponse(id TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	ipLen := 4
	family := byte(familyIPv4)
	if ip.Is6() {
		ipLen = 16
		family = familyIPv6
	}
	attrLen := 4 + ipLen
	b := make([]byte, headerLen+4+attrLen)
	binary.BigEndian.PutUint16(b[0:2], typeBindingResponse)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+attrLen))
	binary.BigEndian.PutUint32(b[4:8], MagicCookie)
	copy(b[8:20], id[:])

	attr := b[headerLen:]
	binary.BigEndian.PutUint16(attr[0:2], attrXorMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], uint16(attrLen))
	attr[4] = 0
	attr[5] = family
	binary.BigEndian.PutUint16(attr[6:8], addr.Port()^(MagicCookie>>16))
	ipBytes := ip.AsSlice()
	xorKey := make([]byte, 16)
	binary.BigEndian.PutUint32(xorKey[0:4], MagicCookie)
	copy(xorKey[4:], id[:])
	for i := 0; i < ipLen; i++ {
		attr[8+i] = ipBytes[i] ^ xorKey[i]
	}
	return b
}

// ParseBindingRequest vérifie une requête Binding et renvoie son TxID.
func ParseBindingRequest(b []byte) (TxID, error) {
	var id TxID
	if !IsMessage(b) {
		return id, errors.New("pas un message STUN")
	}
	if binary.BigEndian.Uint16(b[0:2]) != typeBindingRequest {
		return id, errors.New("pas une requête Binding")
	}
	copy(id[:], b[8:20])
	return id, nil
}

// ParseBindingResponse extrait l'adresse observée d'une réponse Binding
// (XOR-MAPPED-ADDRESS, avec repli sur MAPPED-ADDRESS).
func ParseBindingResponse(b []byte) (TxID, netip.AddrPort, error) {
	var id TxID
	if !IsBindingResponse(b) {
		return id, netip.AddrPort{}, errors.New("pas une réponse Binding")
	}
	copy(id[:], b[8:20])
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+msgLen > len(b) {
		return id, netip.AddrPort{}, errors.New("message tronqué")
	}

	attrs := b[headerLen : headerLen+msgLen]
	var mapped netip.AddrPort
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+attrLen > len(attrs) {
			break
		}
		value := attrs[4 : 4+attrLen]
		switch attrType {
		case attrXorMappedAddress:
			ap, err := decodeAddress(value, id, true)
			if err == nil {
				return id, ap, nil // l'attribut XOR fait foi
			}
		case attrMappedAddress:
			if ap, err := decodeAddress(value, id, false); err == nil {
				mapped = ap
			}
		}
		// Les attributs sont alignés sur 4 octets.
		attrs = attrs[4+((attrLen+3)&^3):]
	}
	if mapped.IsValid() {
		return id, mapped, nil
	}
	return id, netip.AddrPort{}, errors.New("adresse observée absente de la réponse")
}

func decodeAddress(v []byte, id TxID, xored bool) (netip.AddrPort, error) {
	if len(v) < 8 {
		return netip.AddrPort{}, errors.New("attribut trop court")
	}
	ipLen := 4
	if v[1] == familyIPv6 {
		ipLen = 16
	}
	if len(v) < 4+ipLen {
		return netip.AddrPort{}, errors.New("attribut tronqué")
	}
	port := binary.BigEndian.Uint16(v[2:4])
	ipBytes := make([]byte, ipLen)
	copy(ipBytes, v[4:4+ipLen])
	if xored {
		port ^= MagicCookie >> 16
		xorKey := make([]byte, 16)
		binary.BigEndian.PutUint32(xorKey[0:4], MagicCookie)
		copy(xorKey[4:], id[:])
		for i := range ipBytes {
			ipBytes[i] ^= xorKey[i]
		}
	}
	ip, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("adresse invalide (%d octets)", ipLen)
	}
	return netip.AddrPortFrom(ip.Unmap(), port), nil
}
