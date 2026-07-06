#!/bin/sh
set -e
# Recharge systemd ; le service n'est pas activé automatiquement car il
# faut d'abord enrôler la machine (omnid up --server … --auth-key …).
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo "omnid installé. Enrôlez la machine puis activez le service :"
echo "  sudo omnid up --server https://VOTRE_SERVEUR --auth-key omkey-…"
echo "  sudo systemctl enable --now omnid"
