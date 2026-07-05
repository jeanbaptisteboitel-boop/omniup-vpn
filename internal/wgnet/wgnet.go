// Package wgnet gère l'interface réseau WireGuard : création du lien,
// adressage, et synchronisation des pairs via wgctrl.
package wgnet

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// KeepaliveInterval maintient les mappings NAT ouverts entre pairs.
const KeepaliveInterval = 25 * time.Second

// EnsureInterface crée l'interface WireGuard si elle n'existe pas,
// lui attribue ip (au sein de cidr, pour que la route du réseau overlay
// soit installée automatiquement) et l'active.
func EnsureInterface(name, ip, cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("cidr invalide %q: %w", cidr, err)
	}
	ones, _ := ipnet.Mask.Size()

	link, err := netlink.LinkByName(name)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = name
		wg := &netlink.Wireguard{LinkAttrs: la}
		if err := netlink.LinkAdd(wg); err != nil {
			return fmt.Errorf("création de l'interface %s: %w (le module noyau wireguard est-il chargé ?)", name, err)
		}
		link, err = netlink.LinkByName(name)
		if err != nil {
			return err
		}
	}

	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip, ones))
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("adressage de %s: %w", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("activation de %s: %w", name, err)
	}
	return nil
}

// DeleteInterface supprime l'interface (idempotent).
func DeleteInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // déjà absente
	}
	return netlink.LinkDel(link)
}

// Configure applique la clé privée, le port d'écoute et remplace la liste
// complète des pairs de l'interface.
func Configure(name string, privateKey wgtypes.Key, listenPort int, peers []types.Peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer c.Close()

	cfgPeers := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, p := range peers {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue // pair invalide : on l'ignore plutôt que de casser la synchro
		}
		peerIP := net.ParseIP(p.IP)
		if peerIP == nil {
			continue
		}
		keepalive := KeepaliveInterval
		pc := wgtypes.PeerConfig{
			PublicKey:                   pub,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  []net.IPNet{{IP: peerIP, Mask: net.CIDRMask(32, 32)}},
			PersistentKeepaliveInterval: &keepalive,
		}
		if p.Endpoint != "" {
			if ua, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
				pc.Endpoint = ua
			}
		}
		cfgPeers = append(cfgPeers, pc)
	}

	return c.ConfigureDevice(name, wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        cfgPeers,
	})
}

// DeviceInfo renvoie l'état courant de l'interface WireGuard.
func DeviceInfo(name string) (*wgtypes.Device, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Device(name)
}
