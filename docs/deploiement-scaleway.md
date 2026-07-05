# Déployer OmniUp VPN sur un VPS Scaleway

Ce guide part d'une instance Scaleway (n'importe quelle taille — même une
Stardust à ~2 €/mois suffit largement : le serveur ne fait que coordonner)
sous Debian/Ubuntu, et de deux machines Linux à relier.

## 1. Ouvrir les ports (console Scaleway)

Dans la console Scaleway → **Instances** → votre instance → onglet
**Security Groups** (groupe attaché à l'instance) → règles entrantes :

| Protocole | Port | Usage |
|---|---|---|
| TCP | 8080 (ou 443 avec TLS) | API de coordination + console `/admin` |
| UDP | 3478 | STUN (découverte d'endpoint) |
| UDP | 3479 | Relais de secours |

> Si votre groupe de sécurité est en politique « accepter par défaut »
> (le cas des groupes neufs), rien à faire — mais vérifiez.

Notez l'**IP publique** de l'instance (ou associez-lui un nom DNS,
recommandé : `vpn.mondomaine.fr → IP`).

## 2. Installer le serveur de coordination

Connectez-vous en SSH à l'instance, puis **au choix** :

### Option A — Docker (le plus simple)

```sh
# Docker si absent :
curl -fsSL https://get.docker.com | sh

git clone https://github.com/jeanbaptisteboitel-boop/omniup-vpn.git
cd omniup-vpn
docker compose up -d
docker compose logs omni-server     # ← notez la clé admin « omadmin-… »
```

### Option B — binaire + systemd

```sh
# depuis une release :
curl -fsSL -o /usr/local/bin/omni-server \
  https://github.com/jeanbaptisteboitel-boop/omniup-vpn/releases/latest/download/omni-server-linux-amd64
chmod +x /usr/local/bin/omni-server

# ou en compilant sur place (Go 1.24) :
#   git clone … && cd omniup-vpn && make build && cp bin/omni-server /usr/local/bin/

curl -fsSL -o /etc/systemd/system/omni-server.service \
  https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/deploy/systemd/omni-server.service
systemctl daemon-reload
systemctl enable --now omni-server
journalctl -u omni-server | grep omadmin-   # ← la clé admin
```

Vérification : `curl http://IP_DU_VPS:8080/healthz` doit répondre 200, et
`http://IP_DU_VPS:8080/admin` doit afficher la console dans votre
navigateur (connectez-vous avec la clé `omadmin-…`).

## 3. Créer une clé d'enrôlement

Dans la console web (`/admin` → onglet **Clés d'enrôlement**) : cochez
« réutilisable », choisissez l'expiration, **Créer une clé** — copiez le
`omkey-…` affiché.

Ou en CLI depuis le VPS :

```sh
export OMNIUP_ADMIN_KEY=omadmin-…
omni-server genkey --reusable
```

## 4. Connecter vos machines

Sur **chaque machine Linux** à relier (portable, NAS, autre serveur…) :

```sh
curl -fsSL https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/scripts/install-omnid.sh \
  | sudo sh -s -- --server http://IP_DU_VPS:8080 --auth-key omkey-…
```

(Le script télécharge la dernière release, enrôle la machine et active le
service systemd. Sans release publiée : compilez `make build` et lancez
`sudo ./bin/omnid up --server … --auth-key …` puis installez
`deploy/systemd/omnid.service`.)

## 5. Vérifier

```sh
sudo omnid status
# machine    : 100.64.0.1 (omni0)
#   pair serveur-nas (100.64.0.2) — handshake il y a 8s, via 82.65.x.x:41641, …

ping 100.64.0.2          # à travers le tunnel chiffré
ping serveur-nas.omni    # via le DNS interne (voir README pour resolvectl)
```

Dans `omnid status`, la colonne « via » dit tout :
- **`ip:port` public ou LAN** → liaison **directe** (perçage NAT réussi) ;
- **`relay:…`** → liaison **relayée** par le VPS (NAT symétrique des deux
  côtés — ça fonctionne, juste avec la latence du détour).

La console `/admin` montre les machines passer « en ligne » en ~10 s.

## 6. (Recommandé) TLS avec un nom de domaine

En HTTP clair, les clés d'enrôlement et jetons transitent en clair entre
agents et VPS. Avec un domaine pointant sur l'instance, le plus simple est
Caddy en frontal :

```sh
apt install -y caddy
cat > /etc/caddy/Caddyfile <<'EOF'
vpn.mondomaine.fr {
    reverse_proxy 127.0.0.1:8080
}
EOF
systemctl reload caddy
```

Caddy obtient et renouvelle le certificat tout seul (ouvrez 80 et
443/tcp dans le groupe de sécurité ; 8080 peut alors être fermé de
l'extérieur). Côté machines, enrôlez avec
`--server https://vpn.mondomaine.fr` — STUN et relais restent en UDP
directement sur 3478/3479.

## Dépannage

| Symptôme | Piste |
|---|---|
| `poll: … connection refused` | Port 8080/tcp fermé (groupe de sécurité) ou serveur arrêté |
| `endpoints locaux` sans IP publique dans les logs omnid | UDP 3478 fermé → STUN muet ; le perçage se rabat sur l'endpoint observé par le serveur |
| Pairs toujours `relay:…` | Perçage impossible (NAT symétrique) : normal, c'est le rôle du relais ; vérifiez quand même que l'UDP sortant n'est pas filtré côté machines |
| `relais de secours indisponible` | UDP 3479 fermé sur le VPS |
| `création du TUN … /dev/net/tun` | Machine sans TUN (conteneur restreint) : lancez l'agent sur l'hôte |
