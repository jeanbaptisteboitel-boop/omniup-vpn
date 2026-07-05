package wgnet

import (
	"fmt"
	"net"
	"os/exec"
)

// setAddress (Windows) : adressage de l'adaptateur Wintun via netsh ;
// l'adresse portant le masque du réseau overlay, la route on-link du
// sous-réseau est installée automatiquement.
func (d *Device) setAddress(ip string, ipnet *net.IPNet) error {
	mask := net.IP(ipnet.Mask).String()
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+d.Name, "static", ip, mask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address %s: %v (%s)", d.Name, err, out)
	}
	return nil
}
