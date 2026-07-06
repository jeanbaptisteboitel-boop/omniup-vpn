package main

import "os"

// stopProcess arrête le démon. Windows n'a pas de SIGTERM inter-processus :
// on termine le processus, l'adaptateur Wintun disparaît avec lui.
func stopProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
