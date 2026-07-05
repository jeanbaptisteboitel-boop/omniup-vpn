package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// State est l'identité persistée de la machine (survit aux redémarrages).
// Le fichier contient la clé privée WireGuard : il est écrit en mode 0600.
type State struct {
	ServerURL   string `json:"server_url"`
	PrivateKey  string `json:"private_key"`
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	IP          string `json:"ip"`
	CIDR        string `json:"cidr"`
	Iface       string `json:"iface"`
	ListenPort  int    `json:"listen_port"`
}

// LoadState charge l'état depuis path ; renvoie (nil, nil) s'il n'existe pas.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save persiste l'état de façon atomique.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".omnid-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
