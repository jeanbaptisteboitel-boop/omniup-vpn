package control

import "fmt"

// ACLPolicy contrôle la visibilité entre machines. Sans règle (politique
// vide ou absente), tout le monde voit tout le monde. Dès qu'une règle
// existe, tout ce qui n'est pas explicitement autorisé est refusé.
type ACLPolicy struct {
	Rules []ACLRule `json:"rules"`
}

// ACLRule autorise le trafic des machines Src vers les machines Dst.
// Chaque entrée est un nom de machine, une IP du réseau, ou "*".
type ACLRule struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
}

// Validate vérifie que chaque règle a au moins une source et une destination.
func (p *ACLPolicy) Validate() error {
	for i, r := range p.Rules {
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("règle %d : src et dst doivent être non vides", i)
		}
	}
	return nil
}

// Allows indique si la politique autorise le trafic de src vers dst.
func (p *ACLPolicy) Allows(src, dst Device) bool {
	if p == nil || len(p.Rules) == 0 {
		return true
	}
	for _, r := range p.Rules {
		if matchAny(r.Src, src) && matchAny(r.Dst, dst) {
			return true
		}
	}
	return false
}

// Visible indique si a et b doivent se connaître comme pairs WireGuard.
// Un tunnel est nécessaire dès que le trafic est autorisé dans un sens.
func (p *ACLPolicy) Visible(a, b Device) bool {
	return p.Allows(a, b) || p.Allows(b, a)
}

func matchAny(entries []string, d Device) bool {
	for _, e := range entries {
		if e == "*" || e == d.Hostname || e == d.IP {
			return true
		}
	}
	return false
}

func (p *ACLPolicy) clone() *ACLPolicy {
	if p == nil {
		return nil
	}
	cp := &ACLPolicy{Rules: make([]ACLRule, len(p.Rules))}
	for i, r := range p.Rules {
		cp.Rules[i] = ACLRule{
			Src: append([]string(nil), r.Src...),
			Dst: append([]string(nil), r.Dst...),
		}
	}
	return cp
}
