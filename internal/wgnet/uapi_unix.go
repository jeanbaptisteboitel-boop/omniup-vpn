//go:build linux || darwin

package wgnet

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/ipc"
)

// uapiListen expose la socket UAPI standard /var/run/wireguard/<nom>.sock.
func uapiListen(name string) (net.Listener, error) {
	file, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(name, file)
}

// dialUAPI se connecte à la socket UAPI d'un démon en cours.
func dialUAPI(iface string) (net.Conn, error) {
	return net.DialTimeout("unix", "/var/run/wireguard/"+iface+".sock", 2*time.Second)
}
