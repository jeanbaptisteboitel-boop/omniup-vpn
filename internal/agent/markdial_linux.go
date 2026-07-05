package agent

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

// markedHTTPClient construit un client HTTP dont les connexions (et les
// résolutions DNS) portent le fwmark de l'agent : en mode exit node, le
// trafic de contrôle vers le serveur de coordination échappe au tunnel —
// sans quoi le poll passerait par le tunnel qu'il sert à établir.
func markedHTTPClient() *http.Client {
	control := func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, wgnet.Fwmark)
		}); err != nil {
			return err
		}
		return sockErr
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second, Control: control}
			return d.DialContext(ctx, network, address)
		},
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: control, Resolver: resolver}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
}
