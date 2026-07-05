package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/jeanbaptisteboitel-boop/omniup-vpn/internal/agent"
)

const serviceName = "omnid"

// cmdService gère le service Windows : installation (démarrage
// automatique), désinstallation, et exécution sous le contrôle du
// gestionnaire de services (SCM).
func cmdService(args []string) error {
	if len(args) < 1 {
		return errors.New("usage : omnid service install|uninstall|run [options de « up »]")
	}
	switch args[0] {
	case "install":
		return serviceInstall(args[1:])
	case "uninstall":
		return serviceUninstall()
	case "run":
		return serviceRun(args[1:])
	default:
		return fmt.Errorf("sous-commande inconnue %q", args[0])
	}
}

// serviceInstall enregistre le service avec les options de connexion en
// arguments, puis le démarre. La clé d'enrôlement n'est utile qu'au
// premier démarrage (l'identité est ensuite persistée).
func serviceInstall(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("gestionnaire de services (lancez en administrateur ?): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("le service %s existe déjà (« omnid service uninstall » d'abord)", serviceName)
	}

	svcArgs := append([]string{"service", "run"}, args...)
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "OmniUp VPN",
		Description: "Agent OmniUp VPN : réseau mesh WireGuard.",
		StartType:   mgr.StartAutomatic,
	}, svcArgs...)
	if err != nil {
		return fmt.Errorf("création du service: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("service installé mais démarrage impossible: %w", err)
	}
	fmt.Println("service omnid installé et démarré (démarrage automatique au boot)")
	fmt.Printf("journal : %s\n", serviceLogPath())
	return nil
}

func serviceUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("gestionnaire de services (lancez en administrateur ?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s introuvable", serviceName)
	}
	defer s.Close()

	// Arrêt (au mieux) avant suppression.
	if status, err := s.Control(svc.Stop); err == nil {
		deadline := time.Now().Add(10 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("suppression du service: %w", err)
	}
	fmt.Println("service omnid désinstallé")
	return nil
}

// serviceRun est invoqué par le SCM : il journalise dans un fichier et
// fait tourner l'agent jusqu'à l'ordre d'arrêt.
func serviceRun(args []string) error {
	if f, err := os.OpenFile(serviceLogPath(),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		log.SetOutput(f)
	}
	opts := parseUpOptions("service run", args)
	return svc.Run(serviceName, &omnidService{opts: opts})
}

func serviceLogPath() string {
	return filepath.Join(filepath.Dir(defaultStatePath()), "omnid.log")
}

type omnidService struct {
	opts agent.Options
}

// Execute implémente svc.Handler : cycle de vie piloté par le SCM.
func (s *omnidService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.Up(ctx, s.opts) }()

	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			// L'agent s'est arrêté de lui-même (erreur fatale).
			if err != nil {
				log.Printf("service: agent terminé: %v", err)
				status <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}
