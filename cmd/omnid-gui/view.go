package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

// trayView est l'état d'affichage calculé à chaque rafraîchissement,
// indépendant de la bibliothèque systray (donc testable).
type trayView struct {
	Connected bool     // interface montée et au moins un pair joignable
	Title     string   // infobulle / titre
	SelfLine  string   // « cette machine : nom (100.64.0.1) »
	Peers     []string // une entrée lisible par pair
}

// buildView compose la vue à partir de l'identité locale, de l'état de
// l'interface (nil si inactive) et de la carte du réseau (nil si le
// serveur est injoignable).
func buildView(hostname, ip string, ifaceUp bool, nm *types.NetMap, now time.Time) trayView {
	v := trayView{}
	name := hostname
	if name == "" {
		name = ip
	}
	v.SelfLine = fmt.Sprintf("Cette machine : %s (%s)", name, ip)

	if !ifaceUp {
		v.Title = "OmniUp VPN — déconnecté"
		v.Peers = []string{"Interface inactive"}
		return v
	}

	if nm == nil {
		v.Connected = true
		v.Title = "OmniUp VPN — connecté (serveur injoignable)"
		v.Peers = []string{"Serveur de coordination injoignable"}
		return v
	}

	peers := append([]types.Peer(nil), nm.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })
	online := 0
	for _, p := range peers {
		mark := "○"
		if p.Online {
			mark = "●"
			online++
		}
		pname := p.Hostname
		if pname == "" {
			pname = p.IP
		}
		v.Peers = append(v.Peers, fmt.Sprintf("%s %s (%s)", mark, pname, p.IP))
	}
	if len(peers) == 0 {
		v.Peers = []string{"Aucun autre pair sur le réseau"}
	}
	v.Connected = true
	v.Title = fmt.Sprintf("OmniUp VPN — connecté · %d/%d pair(s) en ligne", online, len(peers))
	return v
}
