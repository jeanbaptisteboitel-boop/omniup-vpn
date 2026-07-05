package wgnet

import (
	"fmt"
	"os/exec"
)

func (d *Device) routeAdd(cidr string) error {
	if out, err := exec.Command("netsh", "interface", "ipv4", "add", "route",
		cidr, d.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("%v (%s)", err, out)
	}
	return nil
}

func (d *Device) routeDel(cidr string) error {
	if out, err := exec.Command("netsh", "interface", "ipv4", "delete", "route",
		cidr, d.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("%v (%s)", err, out)
	}
	return nil
}
