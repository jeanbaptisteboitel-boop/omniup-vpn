package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// Client parle à l'API du serveur de coordination.
type Client struct {
	ServerURL string
	Token     string // jeton machine, vide avant l'enregistrement
	http      *http.Client
}

func NewClient(serverURL, token string) *Client {
	return &Client{
		ServerURL: strings.TrimRight(serverURL, "/"),
		Token:     token,
		http:      &http.Client{Timeout: 15 * time.Second},
	}
}

// Register enrôle la machine et renvoie son identité (IP, jeton).
func (c *Client) Register(authKey, hostname, publicKey string) (*types.RegisterResponse, error) {
	var resp types.RegisterResponse
	err := c.do("POST", "/api/v1/register", types.RegisterRequest{
		AuthKey:   authKey,
		Hostname:  hostname,
		PublicKey: publicKey,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Poll signale nos endpoints candidats et récupère la carte du réseau.
func (c *Client) Poll(req types.PollRequest) (*types.NetMap, error) {
	var nm types.NetMap
	if err := c.do("POST", "/api/v1/poll", req, &nm); err != nil {
		return nil, err
	}
	return &nm, nil
}

func (c *Client) do(method, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.ServerURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr types.ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("serveur: %s (HTTP %d)", apiErr.Error, resp.StatusCode)
		}
		return fmt.Errorf("serveur: HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
