# OmniUp VPN

Un VPN mesh auto-hébergé inspiré de Tailscale : chaque machine obtient une
adresse stable sur un réseau overlay privé (`100.64.0.0/24`) et communique
**directement** avec les autres via des tunnels **WireGuard** chiffrés. Un
serveur de coordination léger gère l'enrôlement et distribue la carte des
pairs — il ne voit jamais passer le trafic.

```
                    ┌──────────────────┐
                    │   omni-server    │   plan de contrôle (HTTP)
                    │  (coordination)  │   · enrôlement des machines
                    └───────┬──────────┘   · attribution des IP (IPAM)
              enrôlement,   │   carte       · distribution de la carte
              heartbeat     │   des pairs     des pairs et des endpoints
          ┌─────────────────┼─────────────────┐
          │                 │                 │
     ┌────┴────┐       ┌────┴────┐       ┌────┴────┐
     │  omnid  │◄─────►│  omnid  │◄─────►│  omnid  │   plan de données
     │  alpha  │  WG   │  beta   │  WG   │  gamma  │   (WireGuard, direct)
     │100.64.0.1       │100.64.0.2       │100.64.0.3
     └─────────┘       └─────────┘       └─────────┘
```

## Composants

| Binaire | Rôle |
|---|---|
| `omni-server` | Serveur de coordination : API HTTP, clés d'enrôlement, IPAM, carte du réseau |
| `omnid` | Agent sur chaque machine : clés WireGuard, interface `omni0`, synchronisation des pairs |

## Démarrage rapide

### 1. Compiler

```sh
make build     # produit bin/omni-server et bin/omnid
```

### 2. Lancer le serveur de coordination

Sur une machine joignable par toutes les autres (IP publique ou VPS) :

```sh
./bin/omni-server serve --addr :8080 --state /var/lib/omniup/server.json
```

Au premier démarrage, le serveur affiche sa **clé admin** (`omadmin-…`) —
conservez-la.

### 3. Créer une clé d'enrôlement

```sh
export OMNIUP_ADMIN_KEY=omadmin-…
./bin/omni-server genkey --server http://SERVEUR:8080 --reusable
# → omkey-…
```

(`--reusable` permet d'enrôler plusieurs machines avec la même clé ;
sans ce drapeau la clé est à usage unique.)

### 4. Connecter chaque machine

Sur chaque machine Linux (en root, module noyau `wireguard` requis) :

```sh
sudo ./bin/omnid up --server http://SERVEUR:8080 --auth-key omkey-…
```

L'agent génère ses clés WireGuard, reçoit une adresse (ex. `100.64.0.1`),
monte l'interface `omni0` et synchronise les pairs toutes les 10 s.
L'identité est persistée dans `/var/lib/omniup/omnid.json` : aux démarrages
suivants, `sudo omnid up` suffit (plus besoin de clé).

### 5. Vérifier

```sh
sudo ./bin/omnid status                  # pairs, handshakes, trafic
./bin/omni-server devices --server …     # vue serveur (admin)
ping 100.64.0.2                          # trafic chiffré direct via WireGuard
```

`sudo omnid down` retire l'interface.

## Fonctionnement

1. **Enrôlement** — l'agent génère une paire de clés WireGuard et envoie sa
   clé publique au serveur avec une clé d'enrôlement (`POST /api/v1/register`).
   Le serveur attribue une IP du réseau overlay et renvoie un jeton machine.
2. **Heartbeat** — toutes les 10 s, l'agent appelle `POST /api/v1/poll` en
   déclarant son port UDP WireGuard. Le serveur en déduit l'endpoint public
   de la machine (IP source de la requête + port déclaré) et renvoie la
   carte complète du réseau.
3. **Synchronisation** — l'agent applique la carte à l'interface WireGuard :
   un pair par machine, `AllowedIPs = <ip>/32`, endpoint public si connu,
   keepalive 25 s pour maintenir les mappings NAT. Le trafic circule ensuite
   **directement** entre machines, chiffré de bout en bout — le serveur de
   coordination n'y a jamais accès (il ne connaît que les clés publiques).

## API du serveur

| Méthode | Chemin | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/register` | clé d'enrôlement (corps) | Enrôle une machine, attribue une IP |
| `POST` | `/api/v1/poll` | `Bearer` jeton machine | Heartbeat + carte du réseau (filtrée par les ACLs) |
| `POST` | `/api/v1/authkeys` | `Bearer` clé admin | Crée une clé d'enrôlement (`?reusable=true`) |
| `GET` | `/api/v1/devices` | `Bearer` clé admin | Liste des machines |
| `GET` | `/api/v1/acl` | `Bearer` clé admin | Politique d'accès courante |
| `PUT` | `/api/v1/acl` | `Bearer` clé admin | Remplace la politique d'accès |
| `GET` | `/healthz` | — | Sonde de vie |

## HTTPS

Le serveur sert du HTTPS nativement avec un certificat fourni :

```sh
./bin/omni-server serve --addr :443 --tls-cert cert.pem --tls-key key.pem
```

Sans certificat, il écoute en HTTP clair (un avertissement est journalisé) :
réservez ce mode au développement ou placez un reverse proxy TLS devant.

## ACLs — qui parle à qui

Par défaut, toutes les machines se voient. Dès qu'une politique contient des
règles, tout ce qui n'est pas explicitement autorisé est refusé. Chaque règle
autorise `src → dst` ; les entrées sont des noms de machines, des IP du
réseau, ou `*`.

```sh
cat > politique.json <<'EOF'
{
  "rules": [
    { "src": ["portable-jb"], "dst": ["serveur-nas", "100.64.0.7"] },
    { "src": ["*"],           "dst": ["serveur-web"] }
  ]
}
EOF
./bin/omni-server acl --server http://SERVEUR:8080 --set politique.json
./bin/omni-server acl --server http://SERVEUR:8080   # affiche la politique
```

L'application est faite côté serveur en filtrant la carte des pairs : une
machine ne reçoit jamais les clés ni les endpoints des pairs avec lesquels
aucun échange n'est autorisé (comme Tailscale). Si un sens est autorisé, les
deux machines se connaissent (le tunnel WireGuard est bidirectionnel).

## DNS interne (équivalent MagicDNS)

Chaque agent embarque un petit serveur DNS qui écoute sur son adresse
overlay (port 53) et résout `<machine>.omni` à partir de la carte du réseau :

```sh
dig @100.64.0.1 beta.omni     # → 100.64.0.2
```

Pour l'utiliser de façon transparente, pointez le résolveur du système vers
l'interface (exemple avec systemd-resolved) :

```sh
resolvectl dns omni0 100.64.0.1      # l'adresse overlay de la machine
resolvectl domain omni0 '~omni'
ping beta.omni
```

Désactivable avec `omnid up --dns=false` ; zone configurable via
`--dns-zone`. Les noms sont normalisés en labels DNS valides
(« Mon PC » → `mon-pc`).

## Limites actuelles et feuille de route

Ce MVP couvre le cœur du modèle Tailscale (coordination + WireGuard direct).
Les prochaines étapes, par ordre de priorité :

- [x] **HTTPS** sur le plan de contrôle (`--tls-cert`/`--tls-key`, ou
      reverse proxy)
- [x] **ACLs** : politique d'accès entre machines (qui parle à qui)
- [x] **DNS interne** (équivalent MagicDNS) : `alpha.omni` → `100.64.0.1`
- [ ] **Traversée NAT** : découverte d'endpoint par STUN, perçage UDP
      coordonné (le mécanisme actuel — IP source HTTP + port déclaré — ne
      fonctionne pas derrière un NAT symétrique) ; nécessite de passer à
      WireGuard userspace pour contrôler la socket UDP
- [ ] **Relais** type DERP pour les paires de machines qui ne peuvent pas
      établir de connexion directe
- [ ] Élargir l'IPAM à `100.64.0.0/10`, expiration des clés, révocation de
      machines, rotation des jetons
- [ ] Support macOS/Windows via wireguard-go (userspace)
- [ ] SSO/OIDC pour l'enrôlement à la place des clés pré-partagées

## Développement

```sh
make test    # tests unitaires (plan de contrôle, IPAM, auth)
make vet
```

Arborescence :

```
cmd/omni-server/    binaire serveur de coordination
cmd/omnid/          binaire agent (up / status / down)
internal/types/     structures de l'API agent ↔ serveur
internal/control/   serveur : store persistant, IPAM, handlers HTTP
internal/agent/     agent : client API, identité persistée, boucle de synchro
internal/dnssrv/    DNS interne (<machine>.omni)
internal/wgnet/     interface WireGuard (netlink + wgctrl)
```
