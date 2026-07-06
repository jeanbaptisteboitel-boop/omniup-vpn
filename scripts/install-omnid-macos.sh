#!/bin/sh
# Installe l'agent OmniUp VPN sur macOS : télécharge le binaire de la
# dernière release, enrôle la machine et installe un LaunchDaemon pour le
# démarrage automatique.
#
# Usage :
#   curl -fsSL https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/scripts/install-omnid-macos.sh \
#     | sudo sh -s -- --server https://vpn.omniup.fr --auth-key omkey-…

set -eu

REPO="jeanbaptisteboitel-boop/omniup-vpn"
BIN=/usr/local/bin/omnid
PLIST=/Library/LaunchDaemons/fr.omniup.omnid.plist
STATE="/Library/Application Support/OmniUp/omnid.json"
LABEL=fr.omniup.omnid

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
  arm64)  ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) echo "architecture non gérée: $(uname -m)" >&2; exit 1 ;;
esac

echo "» téléchargement de la dernière release (darwin-${ARCH})…"
URL="https://github.com/${REPO}/releases/latest/download/omnid-darwin-${ARCH}"
curl -fsSL -o "${BIN}.tmp" "$URL"
chmod 0755 "${BIN}.tmp"
# Levée de la quarantaine Gatekeeper (sans objet si téléchargé par curl,
# mais inoffensif et utile si le script est rejoué sur un binaire copié).
xattr -d com.apple.quarantine "${BIN}.tmp" 2>/dev/null || true
mv "${BIN}.tmp" "$BIN"
echo "» omnid $("$BIN" version) installé dans $BIN"

echo "» enrôlement auprès de $SERVER…"
mkdir -p "$(dirname "$STATE")"
"$BIN" up --server "$SERVER" --auth-key "$AUTHKEY" &
UP_PID=$!
sleep 4
kill "$UP_PID" 2>/dev/null || true
wait "$UP_PID" 2>/dev/null || true
[ -f "$STATE" ] || { echo "l'enrôlement a échoué (voir les messages ci-dessus)" >&2; exit 1; }

echo "» installation du LaunchDaemon (démarrage automatique)…"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN}</string>
    <string>up</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Library/Logs/omnid.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/omnid.log</string>
</dict>
</plist>
EOF
chmod 0644 "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load -w "$PLIST"

echo "» terminé. Vérifiez avec : omnid status   (journal : /Library/Logs/omnid.log)"
