//go:build !linux

package omnisock

import "net"

// setSocketMark : SO_MARK n'existe que sous Linux ; sans effet ailleurs.
func setSocketMark(*net.UDPConn, uint32) error { return nil }
