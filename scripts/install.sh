#!/bin/sh
# Builds kiln and installs it as /usr/local/bin/kiln, plus the kiln-dns
# service that answers sandbox DNS queries. Run inside the VM as your user:
#   scripts/install.sh
set -eu
cd "$(dirname "$0")/.."

cargo build --release
sudo install -m 755 target/release/kiln /usr/local/bin/kiln
sudo install -m 644 scripts/kiln-dns.service /etc/systemd/system/kiln-dns.service
sudo systemctl daemon-reload
sudo systemctl enable kiln-dns
sudo systemctl restart kiln-dns
systemctl --no-pager --lines=3 status kiln-dns
