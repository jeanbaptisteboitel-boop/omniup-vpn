//go:build !linux

package agent

import "errors"

// enableForwarding : le rôle de routeur de sous-réseau / exit node n'est
// implémenté que sous Linux pour l'instant.
func enableForwarding(string, string) error {
	return errors.New("le rôle de routeur (advertise-routes / advertise-exit-node) n'est disponible que sous Linux")
}
