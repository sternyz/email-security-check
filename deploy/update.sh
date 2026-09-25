#!/usr/bin/env bash
# Pull the latest code and restart the app. Run on the VM as root:
#   /opt/emailcheck/app/deploy/update.sh
set -euo pipefail

APP_DIR=/opt/emailcheck/app
VENV=/opt/emailcheck/venv

sudo -u emailcheck git -C "$APP_DIR" pull --ff-only
sudo -u emailcheck "$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"

install -m 644 "$APP_DIR/deploy/emailcheck.service" /etc/systemd/system/emailcheck.service
install -m 644 "$APP_DIR/deploy/Caddyfile" /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl restart emailcheck
systemctl reload caddy

sleep 2
systemctl is-active --quiet emailcheck && echo "emailcheck: running" || { echo "emailcheck failed to start"; journalctl -u emailcheck -n 30 --no-pager; exit 1; }
