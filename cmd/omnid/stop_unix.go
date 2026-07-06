//go:build !windows

package main

import "syscall"

// stopProcess arrête proprement le démon (SIGTERM : l'agent journalise
// son arrêt et l'interface disparaît avec lui).
func stopProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}
