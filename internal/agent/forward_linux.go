package agent

import (
	"fmt"
	"os"
	"os/exec"
)

// enableForwarding prépare une machine à servir de routeur de sous-réseau
// ou d'exit node : transfert IP activé, et masquerade du trafic venant du
// réseau overlay (les hôtes du LAN ne connaissent pas 100.64.0.0/10 —
// le NAT de source rend les réponses routables, comme chez Tailscale).
func enableForwarding(iface, overlayCIDR string) error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("ip_forward: %w", err)
	}
	rule := []string{"-t", "nat", "-s", overlayCIDR, "!", "-o", iface, "-j", "MASQUERADE"}
	// Idempotent : on n'ajoute la règle que si elle n'existe pas déjà.
	if exec.Command("iptables", append([]string{"-C", "POSTROUTING"}, rule[2:]...)...).Run() == nil {
		return nil
	}
	if out, err := exec.Command("iptables",
		append([]string{"-t", "nat", "-A", "POSTROUTING"}, rule[2:]...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables masquerade: %v (%s)", err, out)
	}
	return nil
}
