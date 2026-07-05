package wgnet

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// setAddress (Linux) : adressage via netlink ; l'adresse portant le masque
// du réseau overlay, la route du sous-réseau est installée automatiquement.
func (d *Device) setAddress(ip string, ipnet *net.IPNet) error {
	ones, _ := ipnet.Mask.Size()
	link, err := netlink.LinkByName(d.Name)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip, ones))
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("adressage de %s: %w", d.Name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("activation de %s: %w", d.Name, err)
	}
	return nil
}
