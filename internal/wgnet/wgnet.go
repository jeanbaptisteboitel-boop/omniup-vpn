// Package wgnet fait tourner WireGuard en espace utilisateur (wireguard-go)
// sur une interface TUN, avec la socket magique d'omnisock comme transport
// UDP. Aucun module noyau n'est requis, et l'agent garde le contrôle de la
// socket — condition nécessaire au STUN et au perçage NAT.
package wgnet

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// KeepaliveInterval maintient les mappings NAT ouverts entre pairs.
const KeepaliveInterval = 25 * time.Second

// DefaultMTU laisse la place aux en-têtes WireGuard sur les chemins usuels.
const DefaultMTU = 1280

// Device est une interface WireGuard userspace en fonctionnement.
type Device struct {
	Name string // nom réel de l'interface TUN
	Bind *omnisock.Bind

	tun  tun.Device
	dev  *device.Device
	uapi net.Listener

	installedRoutes map[string]bool // routes système posées par SetRoutes
}

// Start crée l'interface TUN, démarre le moteur WireGuard avec la clé
// privée et le port donnés, et expose la socket UAPI standard
// (/var/run/wireguard/<nom>.sock, compatible avec l'outil wg).
func Start(name string, mtu int, privateKey wgtypes.Key, listenPort int, bind *omnisock.Bind) (*Device, error) {
	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("création du TUN %s: %w (/dev/net/tun accessible ?)", name, err)
	}
	realName, err := tunDev.Name()
	if err != nil {
		realName = name
	}
	return StartWithTUN(tunDev, realName, privateKey, listenPort, bind, true)
}

// StartWithTUN démarre le moteur sur un TUN déjà créé (interface réelle,
// ou pile netstack userspace dans les tests). withUAPI expose la socket
// de contrôle standard.
func StartWithTUN(tunDev tun.Device, name string, privateKey wgtypes.Key, listenPort int, bind *omnisock.Bind, withUAPI bool) (*Device, error) {
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("wg(%s): ", name))
	dev := device.NewDevice(tunDev, bind, logger)

	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hexKey(privateKey), listenPort)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configuration initiale: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("activation du moteur: %w", err)
	}

	d := &Device{Name: name, Bind: bind, tun: tunDev, dev: dev, installedRoutes: map[string]bool{}}

	// Socket UAPI : facultative (permet « wg show » et « omnid status »).
	// Socket unix sous Linux/macOS, pipe nommé sous Windows.
	if withUAPI {
		if uapi, err := uapiListen(name); err == nil {
			d.uapi = uapi
			go func() {
				for {
					c, err := uapi.Accept()
					if err != nil {
						return
					}
					go dev.IpcHandle(c)
				}
			}()
		}
	}
	return d, nil
}

// Close arrête le moteur ; l'interface TUN disparaît avec lui.
func (d *Device) Close() {
	if d.uapi != nil {
		_ = d.uapi.Close()
	}
	d.dev.Close()
}

// SetAddress attribue l'adresse overlay (au sein de cidr, pour installer
// la route du réseau) et active l'interface. Implémentation par
// plateforme : netlink (Linux), ifconfig+route (macOS), netsh (Windows).
func (d *Device) SetAddress(ip, cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("cidr invalide %q: %w", cidr, err)
	}
	return d.setAddress(ip, ipnet)
}

// SyncPeers aligne la liste des pairs du moteur sur la carte du réseau,
// sans toucher aux endpoints des pairs déjà présents (préservant le
// roaming WireGuard et les choix du perçage NAT). initialEndpoint donne
// l'endpoint de départ d'un pair nouvellement ajouté.
func (d *Device) SyncPeers(peers []types.Peer, known map[string]bool, initialEndpoint func(types.Peer) string) error {
	var sb strings.Builder
	seen := map[string]bool{}
	for _, p := range peers {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil || net.ParseIP(p.IP) == nil {
			continue // pair invalide : on l'ignore plutôt que de casser la synchro
		}
		seen[p.PublicKey] = true
		fmt.Fprintf(&sb, "public_key=%s\n", hexKey(key))
		if known[p.PublicKey] {
			sb.WriteString("update_only=true\n")
		} else if ep := initialEndpoint(p); ep != "" {
			fmt.Fprintf(&sb, "endpoint=%s\n", ep)
		}
		sb.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&sb, "allowed_ip=%s/32\n", p.IP)
		// Sous-réseaux routés par ce pair (subnet routing / exit node).
		for _, route := range p.Routes {
			if _, _, err := net.ParseCIDR(route); err == nil {
				fmt.Fprintf(&sb, "allowed_ip=%s\n", route)
			}
		}
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", int(KeepaliveInterval.Seconds()))
	}
	for pub := range known {
		if !seen[pub] {
			key, err := wgtypes.ParseKey(pub)
			if err != nil {
				continue
			}
			fmt.Fprintf(&sb, "public_key=%s\nremove=true\n", hexKey(key))
		}
	}
	if sb.Len() == 0 {
		return nil
	}
	if err := d.dev.IpcSet(sb.String()); err != nil {
		return err
	}
	for pub := range known {
		delete(known, pub)
	}
	for pub := range seen {
		known[pub] = true
	}
	return nil
}

// SetRoutes aligne les routes système des sous-réseaux des pairs sur la
// carte du réseau : ajoute les nouvelles, retire celles qui ont disparu.
// (0.0.0.0/0 n'est jamais installé ici — l'exit node a son propre
// mécanisme de policy routing.)
func (d *Device) SetRoutes(cidrs []string) error {
	desired := map[string]bool{}
	for _, c := range cidrs {
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			if ones, _ := ipnet.Mask.Size(); ones > 0 {
				desired[ipnet.String()] = true
			}
		}
	}
	var firstErr error
	for c := range d.installedRoutes {
		if !desired[c] {
			if err := d.routeDel(c); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("retrait de la route %s: %w", c, err)
			}
			delete(d.installedRoutes, c)
		}
	}
	for c := range desired {
		if d.installedRoutes[c] {
			continue
		}
		if err := d.routeAdd(c); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("ajout de la route %s: %w", c, err)
			}
			continue
		}
		d.installedRoutes[c] = true
	}
	return firstErr
}

// SetPeerEndpoint force l'endpoint d'un pair (résultat du perçage NAT).
func (d *Device) SetPeerEndpoint(publicKey string, ep netip.AddrPort) error {
	return d.SetPeerEndpointString(publicKey, ep.String())
}

// SetPeerEndpointString force l'endpoint d'un pair sous forme textuelle —
// "ip:port" ou "relay:<clé>" (bascule sur le relais de secours).
func (d *Device) SetPeerEndpointString(publicKey, ep string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	return d.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hexKey(key), ep))
}

// PeerHandshakes renvoie l'heure du dernier handshake par clé publique
// (base64). Zéro si aucun handshake.
func (d *Device) PeerHandshakes() (map[string]time.Time, error) {
	status, err := d.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	var current string
	for _, line := range strings.Split(status, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			current = base64Key(v)
		case "last_handshake_time_sec":
			if current == "" {
				continue
			}
			var sec int64
			fmt.Sscanf(v, "%d", &sec)
			if sec > 0 {
				out[current] = time.Unix(sec, 0)
			} else {
				out[current] = time.Time{}
			}
		}
	}
	return out, nil
}

func hexKey(k wgtypes.Key) string { return hex.EncodeToString(k[:]) }

func base64Key(hexStr string) string {
	raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil || len(raw) != 32 {
		return ""
	}
	var k wgtypes.Key
	copy(k[:], raw)
	return k.String()
}
