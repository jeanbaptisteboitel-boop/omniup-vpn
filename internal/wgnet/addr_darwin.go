package wgnet

import (
	"fmt"
	"net"
	"os/exec"
)

// setAddress (macOS) : les interfaces utun sont point-à-point — on
// configure l'adresse avec ifconfig puis on route le réseau overlay vers
// l'interface, comme le fait wg-quick sur Darwin.
func (d *Device) setAddress(ip string, ipnet *net.IPNet) error {
	mask := net.IP(ipnet.Mask).String()
	if out, err := exec.Command("ifconfig", d.Name, "inet", ip, ip,
		"netmask", mask, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig %s: %v (%s)", d.Name, err, out)
	}
	// -q n'échoue pas si la route existe déjà (redémarrage de l'agent).
	if out, err := exec.Command("route", "-q", "-n", "add", "-inet",
		ipnet.String(), "-interface", d.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("route add %s: %v (%s)", ipnet, err, out)
	}
	return nil
}
