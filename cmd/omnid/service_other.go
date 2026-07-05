//go:build !windows

package main

import "errors"

// cmdService n'existe que sous Windows ; ailleurs, le démarrage
// automatique passe par systemd (Linux) ou launchd (macOS).
func cmdService([]string) error {
	return errors.New("« omnid service » est réservé à Windows — utilisez systemd (deploy/systemd/) ou launchd (scripts/install-omnid-macos.sh)")
}
