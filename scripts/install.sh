#!/bin/sh
# Builds kiln and installs it as /usr/local/bin/kiln, plus two services: kiln-dns
# answers sandbox DNS queries, kiln-metrics serves Prometheus metrics. Run
# inside the VM as your user:
#   scripts/install.sh
set -eu
cd "$(dirname "$0")/.."

build_dir=${CARGO_TARGET_DIR:-target}
cargo build --locked --release --target-dir "$build_dir"
sudo install -m 755 "$build_dir/release/kiln" /usr/local/bin/kiln
for account in kiln-dns kiln-metrics; do
    if ! getent passwd "$account" >/dev/null; then
        sudo useradd --system --user-group --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "$account"
    fi
    # Refuse an existing interactive/root account instead of silently using it.
    getent passwd "$account" | awk -F: '$3 != 0 && $6 == "/nonexistent" && $7 == "/usr/sbin/nologin" {ok=1} END {exit !ok}'
done
[ "$(id -u kiln-dns)" != "$(id -u kiln-metrics)" ]
sudo install -m 644 scripts/kiln-tmpfiles.conf /etc/tmpfiles.d/kiln.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/kiln.conf
# Upgrade live policies written by rootful versions under restrictive umasks.
# This directory is root-owned and contains only host-created policy files.
sudo find /run/kiln/net/dns -maxdepth 1 -type f -exec chmod 0644 {} +
for service in kiln-network-setup kiln-dns kiln-metrics-collect kiln-metrics; do
    sudo install -m 644 "scripts/$service.service" "/etc/systemd/system/$service.service"
done
sudo install -m 644 scripts/kiln-metrics-collect.timer /etc/systemd/system/kiln-metrics-collect.timer
sudo systemctl daemon-reload
sudo systemctl enable kiln-dns kiln-metrics kiln-metrics-collect.timer
sudo systemctl restart kiln-network-setup kiln-metrics-collect
sudo systemctl restart kiln-metrics-collect.timer
sudo systemctl restart kiln-dns kiln-metrics
systemctl --no-pager --lines=3 status kiln-dns kiln-metrics
