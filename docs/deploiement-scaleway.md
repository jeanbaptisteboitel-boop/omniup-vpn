# Déployer OmniUp VPN sur un VPS Scaleway

Ce guide part d'une instance Scaleway (n'importe quelle taille — même une
Stardust à ~2 €/mois suffit largement : le serveur ne fait que coordonner)
sous Debian/Ubuntu, du domaine **`vpn.omniup.fr`**, et de machines Linux à
relier. Le plan de contrôle est servi en HTTPS via Caddy.

## 0. DNS

Chez votre registrar (ou dans Scaleway Domains si le domaine y est géré),
créez un enregistrement **A** :

```
vpn.omniup.fr.   A   <IP publique de l'instance>
```

Vérifiez la propagation : `dig +short vpn.omniup.fr` doit renvoyer l'IP.

## 1. Ouvrir les ports (console Scaleway)

Dans la console Scaleway → **Instances** → votre instance → onglet
**Security Groups** (groupe attaché à l'instance) → règles entrantes :

| Protocole | Port | Usage |
|---|---|---|
| TCP | 80 | Caddy — challenge Let's Encrypt |
| TCP | 443 | API de coordination + console `/admin` (HTTPS) |
| UDP | 3478 | STUN (découverte d'endpoint) |
| UDP | 3479 | Relais de secours |

> Si votre groupe de sécurité est en politique « accepter par défaut »
> (le cas des groupes neufs), rien à faire — mais vérifiez.
> Le port 8080/tcp n'a **pas** besoin d'être ouvert de l'extérieur :
> omni-server n'écoute qu'en local, Caddy fait le TLS devant.

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

Restreignez ensuite le port API à la machine (Caddy sera devant) : dans
`docker-compose.yml`, remplacez `"8080:8080/tcp"` par
`"127.0.0.1:8080:8080/tcp"` puis `docker compose up -d`. Les ports UDP
3478/3479 restent exposés directement.

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

## 3. TLS avec Caddy

```sh
apt install -y caddy
cat > /etc/caddy/Caddyfile <<'EOF'
vpn.omniup.fr {
    reverse_proxy 127.0.0.1:8080
}
EOF
systemctl reload caddy
```

Caddy obtient et renouvelle le certificat Let's Encrypt tout seul.

Vérification : `curl https://vpn.omniup.fr/healthz` doit répondre 200, et
`https://vpn.omniup.fr/admin` doit afficher la console dans votre
navigateur (connectez-vous avec la clé `omadmin-…`).

## 4. Créer une clé d'enrôlement

Dans la console web (`https://vpn.omniup.fr/admin` → onglet **Clés
d'enrôlement**) : cochez « réutilisable », choisissez l'expiration,
**Créer une clé** — copiez le `omkey-…` affiché.

Ou en CLI depuis le VPS :

```sh
export OMNIUP_ADMIN_KEY=omadmin-…
omni-server genkey --reusable
```

## 5. Connecter vos machines

Sur **chaque machine Linux** à relier (portable, NAS, autre serveur…) :

```sh
curl -fsSL https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/scripts/install-omnid.sh \
  | sudo sh -s -- --server https://vpn.omniup.fr --auth-key omkey-…
```

L'agent en déduit automatiquement le STUN (`vpn.omniup.fr:3478`) et le
relais (`vpn.omniup.fr:3479`) — même hôte, en UDP direct.

(Le script télécharge la dernière release, enrôle la machine et active le
service systemd. Sans release publiée : compilez `make build` et lancez
`sudo ./bin/omnid up --server … --auth-key …` puis installez
`deploy/systemd/omnid.service`.)

## 6. Vérifier

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

## 7. Ouvrir le réseau à d'autres utilisateurs

Chaque utilisateur crée son compte sur `https://vpn.omniup.fr/portal` avec
un code d'invitation, puis connecte ses machines lui-même (le portail lui
donne la commande complète) :

```sh
# sur le VPS, pour chaque personne à inviter :
omni-server invite     # → ominv-… , valable 7 jours
```

Ses machines lui sont rattachées : il ne voit et ne gère que les siennes,
vous gardez la vue complète dans `/admin`.

## 8. (Optionnel) Enrôlement SSO avec Google

Pour enrôler les machines en s'authentifiant avec un compte Google plutôt
qu'avec des clés :

1. [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   → **Créer des identifiants** → **ID client OAuth** → type « Application
   Web » → URI de redirection autorisée :
   `https://vpn.omniup.fr/oidc/callback`. Notez le client ID et le secret.
2. Ajoutez au démarrage du serveur (dans `docker-compose.yml` via `command:`,
   ou `/etc/default/omni-server` → `OPTIONS`) :

   ```
   --public-url https://vpn.omniup.fr
   --oidc-issuer https://accounts.google.com
   --oidc-client-id XXX.apps.googleusercontent.com
   --oidc-allowed-emails jeanbaptiste.boitel@gmail.com
   ```

   et le secret via la variable d'environnement
   `OMNIUP_OIDC_CLIENT_SECRET` (évitez de le mettre en argument).
3. Sur les machines : `sudo omnid up --server https://vpn.omniup.fr`
   (sans `--auth-key`) — une URL s'affiche, ouvrez-la où vous voulez,
   authentifiez-vous, c'est fait.

Fonctionne à l'identique avec tout fournisseur OpenID Connect (Keycloak,
Authentik, Microsoft Entra…) : changez `--oidc-issuer`.

## Dépannage

| Symptôme | Piste |
|---|---|
| `poll: … connection refused` / erreur TLS | 80-443/tcp fermés, Caddy arrêté, ou DNS pas propagé (`dig vpn.omniup.fr`) |
| `endpoints locaux` sans IP publique dans les logs omnid | UDP 3478 fermé → STUN muet ; le perçage se rabat sur l'endpoint observé par le serveur |
| Pairs toujours `relay:…` | Perçage impossible (NAT symétrique) : normal, c'est le rôle du relais ; vérifiez quand même que l'UDP sortant n'est pas filtré côté machines |
| `relais de secours indisponible` | UDP 3479 fermé sur le VPS |
| `création du TUN … /dev/net/tun` | Machine sans TUN (conteneur restreint) : lancez l'agent sur l'hôte |
