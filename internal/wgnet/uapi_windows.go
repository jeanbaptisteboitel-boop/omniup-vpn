package wgnet

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// uapiListen expose le pipe nommé UAPI standard de WireGuard sous Windows.
func uapiListen(name string) (net.Listener, error) {
	return ipc.UAPIListen(name)
}

// dialUAPI se connecte au pipe nommé d'un démon en cours.
func dialUAPI(iface string) (net.Conn, error) {
	return namedpipe.DialTimeout(`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`+iface, 2*time.Second)
}
