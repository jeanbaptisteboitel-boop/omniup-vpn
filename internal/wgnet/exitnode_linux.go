package wgnet

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Fwmark marque le trafic propre de l'agent (socket WireGuard, contrôle)
// pour qu'il échappe au routage via l'exit node — sans quoi les paquets
// chiffrés partiraient dans le tunnel qu'ils transportent (boucle).
const Fwmark = 0x6f6d6e69 // "omni"

// exitTable : table de routage dédiée à l'exit node (technique wg-quick).
const exitTable = 7766

// EnableExitNode route tout le trafic (sauf celui marqué Fwmark) via
// l'interface :
//
//	table 7766 : default dev omni0
//	rule : not fwmark 0x6f6d6e69 → table 7766
//	rule : table main, suppress_prefixlength 0 (préserve les routes LAN)
func (d *Device) EnableExitNode() error {
	// Le moteur applique le fwmark à la socket via bind.SetMark.
	if err := d.dev.IpcSet(fmt.Sprintf("fwmark=%d\n", Fwmark)); err != nil {
		return fmt.Errorf("fwmark: %w", err)
	}

	link, err := netlink.LinkByName(d.Name)
	if err != nil {
		return err
	}
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       all,
		Table:     exitTable,
	}); err != nil {
		return fmt.Errorf("route par défaut (table %d): %w", exitTable, err)
	}

	// Les routes plus précises de la table main (LAN, overlay…) gardent
	// la priorité sur l'exit node.
	suppress := netlink.NewRule()
	suppress.Priority = 5000
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0
	suppress.Family = netlink.FAMILY_V4
	if err := netlink.RuleAdd(suppress); err != nil && !isExist(err) {
		return fmt.Errorf("règle suppress_prefixlength: %w", err)
	}

	rule := netlink.NewRule()
	rule.Priority = 5001
	rule.Mark = Fwmark
	rule.Invert = true
	rule.Table = exitTable
	rule.Family = netlink.FAMILY_V4
	if err := netlink.RuleAdd(rule); err != nil && !isExist(err) {
		return fmt.Errorf("règle fwmark: %w", err)
	}
	return nil
}

// DisableExitNode retire les règles de policy routing (au mieux).
func (d *Device) DisableExitNode() {
	rule := netlink.NewRule()
	rule.Priority = 5001
	rule.Mark = Fwmark
	rule.Invert = true
	rule.Table = exitTable
	rule.Family = netlink.FAMILY_V4
	_ = netlink.RuleDel(rule)

	suppress := netlink.NewRule()
	suppress.Priority = 5000
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0
	suppress.Family = netlink.FAMILY_V4
	_ = netlink.RuleDel(suppress)
	// La route de la table 7766 disparaît avec l'interface.
}

func isExist(err error) bool {
	return err == unix.EEXIST
}
