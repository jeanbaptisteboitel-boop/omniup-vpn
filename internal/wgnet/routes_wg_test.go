package wgnet

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/omnisock"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// TestSyncPeersRoutes vérifie que les routes d'un pair deviennent des
// AllowedIPs dans le moteur WireGuard (et disparaissent avec elles).
func TestSyncPeersRoutes(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.97.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := StartWithTUN(tunDev, "routes-test", priv, 0, omnisock.New(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	known := map[string]bool{}
	peer := types.Peer{
		PublicKey: peerKey.PublicKey().String(),
		IP:        "100.97.0.2",
		Routes:    []string{"192.168.50.0/24", "0.0.0.0/0", "pas-un-cidr"},
	}
	if err := dev.SyncPeers([]types.Peer{peer}, known, func(types.Peer) string { return "" }); err != nil {
		t.Fatal(err)
	}

	status, err := dev.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"allowed_ip=100.97.0.2/32",
		"allowed_ip=192.168.50.0/24",
		"allowed_ip=0.0.0.0/0",
	} {
		if !strings.Contains(status, want) {
			t.Fatalf("%s absent de la configuration:\n%s", want, status)
		}
	}
	if strings.Contains(status, "pas-un-cidr") {
		t.Fatal("une route invalide ne doit pas atteindre le moteur")
	}

	// Mise à jour : la route de sous-réseau disparaît.
	peer.Routes = []string{"192.168.50.0/24"}
	if err := dev.SyncPeers([]types.Peer{peer}, known, func(types.Peer) string { return "" }); err != nil {
		t.Fatal(err)
	}
	status, _ = dev.dev.IpcGet()
	if strings.Contains(status, "allowed_ip=0.0.0.0/0") {
		t.Fatalf("0.0.0.0/0 devrait avoir été retiré:\n%s", status)
	}
	if !strings.Contains(status, "allowed_ip=192.168.50.0/24") {
		t.Fatal("la route de sous-réseau devrait rester")
	}
}
