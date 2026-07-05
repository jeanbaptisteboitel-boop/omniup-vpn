# OmniUp VPN

Un VPN mesh auto-hébergé inspiré de Tailscale : chaque machine obtient une
adresse stable sur un réseau overlay privé (`100.64.0.0/24`) et communique
**directement** avec les autres via des tunnels **WireGuard** chiffrés. Un
serveur de coordination léger gère l'enrôlement et distribue la carte des
pairs — il ne voit jamais passer le trafic.

L'agent fait tourner WireGuard **en espace utilisateur** (wireguard-go sur
TUN — aucun module noyau requis) au-dessus d'une « socket magique » qui
partage l'unique socket UDP entre trois protocoles : les paquets WireGuard,
le **STUN** (découverte de l'endpoint public du port réellement utilisé par
les tunnels) et les sondes « **disco** » de perçage NAT — le même principe
que le magicsock de Tailscale, en miniature.

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

Ouvrez aussi les ports UDP 3478 (STUN, `--stun-addr`) et 3479 (relais de
secours, `--relay-addr`) vers le serveur — chacun désactivable avec `off`.
La plage d'adresses du réseau se choisit au premier démarrage :
`--cidr 100.64.0.0/16` par exemple (jusqu'à `/10` ; figée ensuite dans
l'état, en changer implique de ré-enrôler les machines).

### 4. Connecter chaque machine

Sur chaque machine Linux (en root ; `/dev/net/tun` suffit, aucun module
noyau n'est requis) :

```sh
sudo ./bin/omnid up --server http://SERVEUR:8080 --auth-key omkey-…
```

L'agent génère ses clés WireGuard, reçoit une adresse (ex. `100.64.0.1`),
monte l'interface `omni0` (userspace) et synchronise les pairs toutes les
10 s. L'identité est persistée dans `/var/lib/omniup/omnid.json` : aux
démarrages suivants, `sudo omnid up` suffit (plus besoin de clé).
L'interface vit avec le démon : elle disparaît à son arrêt, et
`sudo omnid down` arrête le démon en cours.

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
2. **Découverte d'endpoints** — l'agent interroge le serveur STUN *depuis
   sa socket WireGuard* (le mapping NAT dépend du port source : il faut
   sonder le bon) et collecte ses adresses locales. Cette liste ordonnée de
   candidats — public STUN d'abord, puis LAN — est déclarée au serveur.
3. **Heartbeat** — toutes les 10 s, l'agent appelle `POST /api/v1/poll` avec
   ses candidats. Le serveur y ajoute l'endpoint qu'il observe lui-même et
   renvoie la carte complète du réseau (filtrée par les ACLs).
4. **Perçage NAT** — pour chaque pair sans handshake récent, l'agent envoie
   des sondes « disco » ping/pong vers **tous** les candidats du pair depuis
   la socket WireGuard. L'envoi ouvre le mapping NAT sortant ; les deux
   pairs le faisant simultanément, les chemins se percent. Le premier pong
   reçu désigne le chemin fonctionnel, appliqué comme endpoint du pair
   (les machines d'un même LAN se trouvent ainsi en direct, sans détour).
5. **Relais de secours** — si le perçage n'aboutit pas (NAT symétrique des
   deux côtés), le pair bascule sur un endpoint `relay:<clé>` : ses paquets
   WireGuard transitent, toujours chiffrés, par le relais UDP du serveur
   (équivalent DERP). Les sondes directes continuent en arrière-plan : dès
   qu'un chemin direct répond, le pair sort du relais automatiquement.
6. **Trafic** — `AllowedIPs = <ip>/32` par pair, keepalive 25 s. Le trafic
   circule **directement** entre machines dès que possible, chiffré de bout
   en bout — ni le serveur de coordination ni le relais ne peuvent le
   déchiffrer (ils ne connaissent que les clés publiques) ; les sondes
   disco ne transportent aucune donnée.

L'interface expose la socket UAPI standard (`/var/run/wireguard/omni0.sock`) :
`wg show omni0` et `omnid status` fonctionnent tous les deux.

## API du serveur

| Méthode | Chemin | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/register` | clé d'enrôlement (corps) | Enrôle une machine, attribue une IP |
| `POST` | `/api/v1/poll` | `Bearer` jeton machine | Heartbeat + carte du réseau (filtrée par les ACLs) |
| `POST` | `/api/v1/authkeys` | `Bearer` clé admin | Crée une clé d'enrôlement (`?reusable=true`) |
| `GET` | `/api/v1/devices` | `Bearer` clé admin | Liste des machines |
| `DELETE` | `/api/v1/devices/{cible}` | `Bearer` clé admin | Révoque une machine (IP, nom ou id) |
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
- [x] **WireGuard userspace** avec socket magique (aucun module noyau requis)
- [x] **Traversée NAT** : découverte d'endpoint par STUN sur la socket
      WireGuard, candidats multiples (public + LAN), perçage UDP par sondes
      disco (reste hors de portée : le NAT symétrique des deux côtés)
- [x] **Relais de secours** type DERP (UDP, embarqué dans omni-server) avec
      bascule automatique et retour au direct dès qu'un chemin perce
- [x] **IPAM configurable** (`--cidr`, jusqu'à `100.64.0.0/10`) et
      **révocation de machines** (`omni-server revoke`)
- [ ] Enregistrement authentifié auprès du relais (aujourd'hui : un tiers
      connaissant une clé publique peut détourner ses trames relayées —
      sans pouvoir les déchiffrer ; l'impact se limite à un déni de service)
- [ ] Expiration des clés d'enrôlement, rotation des jetons
- [ ] Support macOS/Windows (le moteur userspace rend le portage possible ;
      il reste l'adressage et les routes par plateforme)
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
internal/agent/     agent : client API, identité, candidats, perçage NAT
internal/dnssrv/    DNS interne (<machine>.omni)
internal/omnisock/  socket magique : conn.Bind partagé WireGuard/STUN/disco/relais
internal/relay/     relais de secours (équivalent DERP, UDP)
internal/stun/      STUN minimal (RFC 5389, Binding + XOR-MAPPED-ADDRESS)
internal/wgnet/     moteur WireGuard userspace (TUN, UAPI, netlink)
```

Le test `internal/wgnet/e2e_test.go` fait dialoguer deux moteurs WireGuard
complets à travers deux sockets magiques (piles réseau userspace netstack) :
le chiffrement, le transport et le roaming sont exercés pour de vrai, sans
privilèges ni module noyau.
