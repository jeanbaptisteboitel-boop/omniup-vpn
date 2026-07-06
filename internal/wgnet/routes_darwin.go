package wgnet

import (
	"fmt"
	"os/exec"
)

func (d *Device) routeAdd(cidr string) error {
	if out, err := exec.Command("route", "-q", "-n", "add", "-inet", cidr,
		"-interface", d.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("%v (%s)", err, out)
	}
	return nil
}

func (d *Device) routeDel(cidr string) error {
	if out, err := exec.Command("route", "-q", "-n", "delete", "-inet",
		cidr).CombinedOutput(); err != nil {
		return fmt.Errorf("%v (%s)", err, out)
	}
	return nil
}
