package wgnet

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
)

// TestKernelRouteInstall pose de vraies routes noyau sur une vraie
// interface TUN. Nécessite root et /dev/net/tun (skippé sinon, notamment
// en CI où les tests ne tournent pas en root).
func TestKernelRouteInstall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root requis")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun indisponible")
	}

	priv, _ := wgtypes.GeneratePrivateKey()
	dev, err := Start("omnirt0", 1280, priv, 0, omnisock.New())
	if err != nil {
		t.Skipf("création TUN impossible: %v", err)
	}
	defer dev.Close()
	if err := dev.SetAddress("100.96.0.1", "100.96.0.0/24"); err != nil {
		t.Fatal(err)
	}

	kernelHasRoute := func(cidr string) bool {
		link, err := netlink.LinkByName(dev.Name)
		if err != nil {
			return false
		}
		routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
		if err != nil {
			return false
		}
		_, want, _ := net.ParseCIDR(cidr)
		for _, r := range routes {
			if r.Dst != nil && r.Dst.String() == want.String() {
				return true
			}
		}
		return false
	}

	if err := dev.SetRoutes([]string{"192.168.150.0/24", "10.99.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if !kernelHasRoute("192.168.150.0/24") || !kernelHasRoute("10.99.0.0/16") {
		t.Fatal("les routes devraient être dans la table noyau")
	}

	// Retrait partiel : une reste, l'autre disparaît.
	if err := dev.SetRoutes([]string{"192.168.150.0/24"}); err != nil {
		t.Fatal(err)
	}
	if kernelHasRoute("10.99.0.0/16") {
		t.Fatal("la route retirée est encore dans la table noyau")
	}
	if !kernelHasRoute("192.168.150.0/24") {
		t.Fatal("la route conservée a disparu")
	}
}
