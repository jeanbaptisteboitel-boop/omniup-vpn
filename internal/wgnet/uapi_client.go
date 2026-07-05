package wgnet

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerStatus est l'état d'un pair tel que rapporté par le moteur WireGuard.
type PeerStatus struct {
	PublicKey     string // base64
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// DeviceStatus est l'état de l'interface, lu via la socket UAPI.
type DeviceStatus struct {
	ListenPort int
	Peers      []PeerStatus
}

// QueryStatus interroge la socket UAPI d'une interface (celle qu'expose le
// démon omnid) — utilisable depuis un autre processus, comme « wg show ».
func QueryStatus(iface string) (*DeviceStatus, error) {
	conn, err := dialUAPI(iface)
	if err != nil {
		return nil, fmt.Errorf("démon omnid inactif pour %s ? (%w)", iface, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("get=1\n\n")); err != nil {
		return nil, err
	}

	st := &DeviceStatus{}
	var cur *PeerStatus
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "listen_port":
			st.ListenPort, _ = strconv.Atoi(v)
		case "public_key":
			st.Peers = append(st.Peers, PeerStatus{PublicKey: base64Key(v)})
			cur = &st.Peers[len(st.Peers)-1]
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 {
					cur.LastHandshake = time.Unix(sec, 0)
				}
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "errno":
			if v != "0" {
				return nil, fmt.Errorf("erreur UAPI errno=%s", v)
			}
		}
	}
	return st, sc.Err()
}
