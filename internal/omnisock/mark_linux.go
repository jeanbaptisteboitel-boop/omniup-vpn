package omnisock

import (
	"net"

	"golang.org/x/sys/unix"
)

// setSocketMark applique SO_MARK à la socket : ses paquets échappent aux
// règles de policy routing de l'exit node (anti-boucle).
func setSocketMark(udp *net.UDPConn, mark uint32) error {
	raw, err := udp.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	return sockErr
}
