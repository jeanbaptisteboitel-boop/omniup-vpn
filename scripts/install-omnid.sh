#!/bin/sh
# Installe l'agent OmniUp VPN sur une machine Linux (systemd) :
# télécharge le binaire de la dernière release, enrôle la machine et
# active le service.
#
# Usage :
#   curl -fsSL https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/scripts/install-omnid.sh \
#     | sudo sh -s -- --server https://vpn.example.com --auth-key omkey-…
#
# Options supplémentaires (--iface, --port, --dns…) : ajoutez-les après
# l'installation dans /etc/default/omnid (variable OPTIONS).

set -eu

REPO="jeanbaptisteboitel-boop/omniup-vpn"
BIN=/usr/local/bin/omnid
UNIT=/etc/systemd/system/omnid.service

SERVER=""
AUTHKEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server)   SERVER="$2"; shift 2 ;;
    --auth-key) AUTHKEY="$2"; shift 2 ;;
    *) echo "option inconnue: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SERVER" ] || { echo "--server est requis" >&2; exit 2; }
[ -n "$AUTHKEY" ] || { echo "--auth-key est requis" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "lancez ce script en root (sudo)" >&2; exit 1; }

case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "architecture non gérée: $(uname -m)" >&2; exit 1 ;;
esac

echo "» téléchargement de la dernière release (linux-${ARCH})…"
URL="https://github.com/${REPO}/releases/latest/download/omnid-linux-${ARCH}"
curl -fsSL -o "${BIN}.tmp" "$URL"
chmod 0755 "${BIN}.tmp"
mv "${BIN}.tmp" "$BIN"
echo "» omnid $("$BIN" version) installé dans $BIN"

echo "» enrôlement auprès de $SERVER…"
mkdir -p /var/lib/omniup
# « up » en avant-plan le temps de l'enrôlement, puis on laisse systemd gérer.
"$BIN" up --server "$SERVER" --auth-key "$AUTHKEY" &
UP_PID=$!
sleep 4
kill "$UP_PID" 2>/dev/null || true
wait "$UP_PID" 2>/dev/null || true
[ -f /var/lib/omniup/omnid.json ] || { echo "l'enrôlement a échoué (voir les messages ci-dessus)" >&2; exit 1; }

echo "» installation du service systemd…"
cat > "$UNIT" <<'EOF'
[Unit]
Description=OmniUp VPN — agent
Documentation=https://github.com/jeanbaptisteboitel-boop/omniup-vpn
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/omnid
ExecStart=/usr/local/bin/omnid up $OPTIONS
Restart=on-failure
RestartSec=5
DeviceAllow=/dev/net/tun rw
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now omnid

echo "» terminé. Vérifiez avec : omnid status"
