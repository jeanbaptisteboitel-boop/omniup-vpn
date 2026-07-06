package main

import (
	"strings"
	"testing"
	"time"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
)

func TestBuildViewDisconnected(t *testing.T) {
	v := buildView("portable", "100.64.0.1", false, nil, time.Now())
	if v.Connected {
		t.Fatal("interface inactive : ne devrait pas être « connecté »")
	}
	if !strings.Contains(v.Title, "déconnecté") {
		t.Fatalf("titre inattendu: %q", v.Title)
	}
	if !strings.Contains(v.SelfLine, "100.64.0.1") {
		t.Fatalf("ligne locale inattendue: %q", v.SelfLine)
	}
}

func TestBuildViewServerUnreachable(t *testing.T) {
	v := buildView("portable", "100.64.0.1", true, nil, time.Now())
	if !v.Connected {
		t.Fatal("interface montée : devrait être connecté même sans serveur")
	}
	if len(v.Peers) != 1 || !strings.Contains(v.Peers[0], "injoignable") {
		t.Fatalf("pairs inattendus: %v", v.Peers)
	}
}

func TestBuildViewConnectedWithPeers(t *testing.T) {
	nm := &types.NetMap{
		Self: types.Peer{Hostname: "portable", IP: "100.64.0.1"},
		Peers: []types.Peer{
			{Hostname: "nas", IP: "100.64.0.3", Online: false},
			{Hostname: "vps", IP: "100.64.0.2", Online: true},
		},
	}
	v := buildView("portable", "100.64.0.1", true, nm, time.Now())
	if !v.Connected {
		t.Fatal("devrait être connecté")
	}
	if !strings.Contains(v.Title, "1/2") {
		t.Fatalf("le titre devrait indiquer 1/2 en ligne: %q", v.Title)
	}
	// Tri par IP : vps (.2) avant nas (.3).
	if len(v.Peers) != 2 || !strings.Contains(v.Peers[0], "vps") || !strings.Contains(v.Peers[1], "nas") {
		t.Fatalf("pairs mal ordonnés: %v", v.Peers)
	}
	// Marqueur en ligne / hors ligne.
	if !strings.HasPrefix(v.Peers[0], "●") || !strings.HasPrefix(v.Peers[1], "○") {
		t.Fatalf("marqueurs d'état incorrects: %v", v.Peers)
	}
}

func TestBuildViewNoPeers(t *testing.T) {
	nm := &types.NetMap{Self: types.Peer{Hostname: "seule", IP: "100.64.0.1"}}
	v := buildView("seule", "100.64.0.1", true, nm, time.Now())
	if len(v.Peers) != 1 || !strings.Contains(v.Peers[0], "Aucun") {
		t.Fatalf("devrait indiquer l'absence de pairs: %v", v.Peers)
	}
}
