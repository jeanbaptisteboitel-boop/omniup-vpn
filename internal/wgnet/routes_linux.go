package wgnet

import (
	"net"

	"github.com/vishvananda/netlink"
)

func (d *Device) routeAdd(cidr string) error {
	link, err := netlink.LinkByName(d.Name)
	if err != nil {
		return err
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst})
}

func (d *Device) routeDel(cidr string) error {
	link, err := netlink.LinkByName(d.Name)
	if err != nil {
		return nil // interface disparue : rien à retirer
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst})
}
