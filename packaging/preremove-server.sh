#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now omni-server 2>/dev/null || true
fi
