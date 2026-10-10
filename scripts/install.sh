#!/bin/sh
# Builds kiln and installs it as /usr/local/bin/kiln, plus two services: kiln-dns
# answers sandbox DNS queries, kiln-metrics serves Prometheus metrics. Run
# inside the VM as your user:
#   scripts/install.sh
set -eu
cd "$(dirname "$0")/.."

cargo build --release
sudo install -m 755 target/release/kiln /usr/local/bin/kiln
for service in kiln-dns kiln-metrics; do
    sudo install -m 644 "scripts/$service.service" "/etc/systemd/system/$service.service"
done
sudo systemctl daemon-reload
sudo systemctl enable kiln-dns kiln-metrics
sudo systemctl restart kiln-dns kiln-metrics
systemctl --no-pager --lines=3 status kiln-dns kiln-metrics
