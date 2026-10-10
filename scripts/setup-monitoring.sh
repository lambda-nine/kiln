#!/bin/sh
# Installs Prometheus and Grafana in the VM, pointed at kiln's exporters, with
# the kiln dashboard ready to use. Run inside the VM as your user, after
# scripts/install.sh (which starts the exporters):
#   scripts/setup-monitoring.sh
# Then open http://localhost:3000 on the Mac (Lima forwards the port).
# Safe to re-run: it just copies the latest config and dashboard again.
set -eu
cd "$(dirname "$0")/.."

# Prometheus and node_exporter come from Ubuntu. Grafana isn't packaged by
# Ubuntu, so add Grafana's own apt repository, trusting only its key.
if ! command -v grafana-server >/dev/null; then
    sudo mkdir -p /etc/apt/keyrings
    wget -qO- https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg >/dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" |
        sudo tee /etc/apt/sources.list.d/grafana.list >/dev/null
fi
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q prometheus prometheus-node-exporter grafana

# Copies, not symlinks: the repo is a mount from the Mac, which isn't there
# yet when these services start at boot.
sudo install -m 644 monitoring/prometheus.yml /etc/prometheus/prometheus.yml
sudo install -m 644 monitoring/grafana/provisioning/datasources/kiln.yaml /etc/grafana/provisioning/datasources/kiln.yaml
sudo install -m 644 monitoring/grafana/provisioning/dashboards/kiln.yaml /etc/grafana/provisioning/dashboards/kiln.yaml
sudo install -d /var/lib/grafana/dashboards/kiln
sudo install -m 644 monitoring/grafana/dashboards/kiln.json /var/lib/grafana/dashboards/kiln/kiln.json

# Grafana settings as environment variables (GF_<SECTION>_<KEY>), in a
# systemd drop-in so grafana.ini stays as packaged. Anonymous visitors can
# view dashboards without logging in; the port is only reachable from the Mac.
# Log in as admin/admin (Grafana asks for a new password) to edit.
sudo install -d /etc/systemd/system/grafana-server.service.d
sudo tee /etc/systemd/system/grafana-server.service.d/kiln.conf >/dev/null <<'CONF'
[Service]
Environment=GF_AUTH_ANONYMOUS_ENABLED=true
Environment=GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
Environment=GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/kiln/kiln.json
Environment=GF_ANALYTICS_REPORTING_ENABLED=false
Environment=GF_ANALYTICS_CHECK_FOR_UPDATES=false
Environment=GF_NEWS_NEWS_FEED_ENABLED=false
CONF

sudo systemctl daemon-reload
sudo systemctl enable --now prometheus prometheus-node-exporter grafana-server
sudo systemctl restart prometheus grafana-server

echo "Waiting for Grafana..."
for _ in $(seq 60); do
    curl -sf http://127.0.0.1:3000/api/health >/dev/null && break
    sleep 1
done
curl -sf http://127.0.0.1:3000/api/health >/dev/null || { echo "Grafana didn't come up: journalctl -u grafana-server"; exit 1; }
echo "Prometheus: http://localhost:9090/targets"
echo "Grafana:    http://localhost:3000 (kiln dashboard)"
