#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo "omni-server installé. Configurez /etc/default/omni-server puis :"
echo "  sudo systemctl enable --now omni-server"
echo "  journalctl -u omni-server | grep omadmin-   # clé admin (premier démarrage)"
