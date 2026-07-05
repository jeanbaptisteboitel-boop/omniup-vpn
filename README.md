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
| `POST` | `/api/v1/poll` | `Bearer` jeton machine | Heartbeat + carte du réseau |
| `POST` | `/api/v1/authkeys` | `Bearer` clé admin | Crée une clé d'enrôlement (`?reusable=true`) |
| `GET` | `/api/v1/devices` | `Bearer` clé admin | Liste des machines |
| `GET` | `/healthz` | — | Sonde de vie |

## Limites actuelles et feuille de route

Ce MVP couvre le cœur du modèle Tailscale (coordination + WireGuard direct).
Les prochaines étapes, par ordre de priorité :

- [ ] **HTTPS** sur le plan de contrôle (TLS natif ou reverse proxy) — en
      attendant, ne pas exposer le serveur en HTTP clair sur Internet
- [ ] **Traversée NAT** : découverte d'endpoint par STUN, perçage UDP
      coordonné (le mécanisme actuel — IP source HTTP + port déclaré — ne
      fonctionne pas derrière un NAT symétrique)
- [ ] **Relais** type DERP pour les paires de machines qui ne peuvent pas
      établir de connexion directe
- [ ] **ACLs** : politique d'accès entre machines (qui parle à qui)
- [ ] **DNS interne** (équivalent MagicDNS) : `alpha.omni` → `100.64.0.1`
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
internal/wgnet/     interface WireGuard (netlink + wgctrl)
```
