//go:build !linux

package wgnet

import "errors"

// Fwmark (sans effet hors Linux, où SO_MARK n'existe pas).
const Fwmark = 0x6f6d6e69

// EnableExitNode n'est implémenté que sous Linux pour l'instant.
func (d *Device) EnableExitNode() error {
	return errors.New("--exit-node n'est disponible que sous Linux pour l'instant")
}

// DisableExitNode : sans objet hors Linux.
func (d *Device) DisableExitNode() {}
