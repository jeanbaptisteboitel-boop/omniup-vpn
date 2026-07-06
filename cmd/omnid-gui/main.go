// omnid-gui est l'application de barre d'état (systray) d'OmniUp VPN :
// une icône qui indique l'état de connexion, la liste des machines du
// réseau, et des raccourcis vers la console web. Elle lit l'identité
// persistée par l'agent omnid et interroge le serveur de coordination.
//
// Elle ne remplace pas le démon omnid (qui monte le tunnel) : c'est un
// tableau de bord. Compilation native uniquement (systray utilise les API
// graphiques de chaque OS) — non incluse dans « make dist » (statique).
package main

import (
	_ "embed"
	"flag"
	"log"
	"os/exec"
	"runtime"
	"time"

	"fyne.io/systray"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/agent"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/types"
	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/wgnet"
)

//go:embed icons/connected.png
var iconConnected []byte

//go:embed icons/disconnected.png
var iconDisconnected []byte

// maxPeerItems : nombre d'entrées de pairs pré-allouées dans le menu
// (systray ne permet pas d'ajouter des items après le démarrage).
const maxPeerItems = 64

var statePath = flag.String("state", "", "fichier d'identité de l'agent (défaut : emplacement standard de l'OS)")

type ui struct {
	self      *systray.MenuItem
	peers     []*systray.MenuItem
	openPortal *systray.MenuItem
	refresh   *systray.MenuItem
	quit      *systray.MenuItem
	state     *agent.State
}

func main() {
	flag.Parse()
	systray.Run(onReady, func() {})
}

func onReady() {
	systray.SetTitle("OmniUp")
	systray.SetTooltip("OmniUp VPN")
	systray.SetIcon(iconDisconnected)

	u := &ui{}
	u.self = systray.AddMenuItem("Chargement…", "")
	u.self.Disable()
	systray.AddSeparator()
	for i := 0; i < maxPeerItems; i++ {
		it := systray.AddMenuItem("", "")
		it.Hide()
		u.peers = append(u.peers, it)
	}
	systray.AddSeparator()
	u.openPortal = systray.AddMenuItem("Ouvrir la console web", "Gérer mes machines dans le navigateur")
	u.refresh = systray.AddMenuItem("Rafraîchir", "")
	u.quit = systray.AddMenuItem("Quitter", "Fermer l'icône (le VPN reste actif)")

	go u.loop()
}

func (u *ui) loop() {
	u.update()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			u.update()
		case <-u.refresh.ClickedCh:
			u.update()
		case <-u.openPortal.ClickedCh:
			if u.state != nil && u.state.ServerURL != "" {
				openBrowser(u.state.ServerURL + "/portal")
			}
		case <-u.quit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

// update recharge l'état et rafraîchit le menu.
func (u *ui) update() {
	path := *statePath
	if path == "" {
		path = agent.DefaultStatePath()
	}
	st, err := agent.LoadState(path)
	if err != nil || st == nil {
		u.render(trayView{Title: "OmniUp VPN — non configuré",
			SelfLine: "Aucune machine enrôlée", Peers: []string{"Lancez « omnid up »"}})
		return
	}
	u.state = st

	ifaceUp := false
	if _, err := wgnet.QueryStatus(st.Iface); err == nil {
		ifaceUp = true
	}
	var nm *types.NetMap
	if ifaceUp {
		if m, err := agent.NewClient(st.ServerURL, st.DeviceToken).Poll(
			types.PollRequest{ListenPort: st.ListenPort}); err == nil {
			nm = m
		}
	}
	hostname := ""
	if nm != nil {
		hostname = nm.Self.Hostname
	}
	u.render(buildView(hostname, st.IP, ifaceUp, nm, time.Now()))
}

func (u *ui) render(v trayView) {
	if v.Connected {
		systray.SetIcon(iconConnected)
	} else {
		systray.SetIcon(iconDisconnected)
	}
	systray.SetTooltip(v.Title)
	u.self.SetTitle(v.SelfLine)
	for i, it := range u.peers {
		if i < len(v.Peers) {
			it.SetTitle(v.Peers[i])
			it.Show()
		} else {
			it.Hide()
		}
	}
}

// openBrowser ouvre une URL dans le navigateur par défaut de l'OS.
func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	if err := exec.Command(cmd, args...).Start(); err != nil {
		log.Printf("ouverture du navigateur: %v", err)
	}
}
