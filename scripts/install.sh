#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo ./scripts/install.sh" >&2
  exit 1
fi

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y python3 python3-venv iw aircrack-ng tshark hostapd dnsmasq nftables sudo

if ! id pinepi >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pinepi --create-home --shell /usr/sbin/nologin pinepi
fi

install -d -o root -g root -m 0755 /opt/pinepi /etc/pinepi
install -d -o root -g pinepi -m 0750 /var/lib/pinepi/scans /var/lib/pinepi/captures
cp -a "${PROJECT_DIR}/app" "${PROJECT_DIR}/requirements.txt" /opt/pinepi/
python3 -m venv /opt/pinepi/.venv
/opt/pinepi/.venv/bin/pip install --upgrade pip
/opt/pinepi/.venv/bin/pip install -r /opt/pinepi/requirements.txt
install -o root -g root -m 0755 "${PROJECT_DIR}/scripts/pinepi-helper" /usr/local/sbin/pinepi-helper
if [[ ! -e /etc/pinepi/pinepi.toml ]]; then
  install -o root -g pinepi -m 0640 "${PROJECT_DIR}/config/pinepi.example.toml" /etc/pinepi/pinepi.toml
fi
install -o root -g root -m 0440 "${PROJECT_DIR}/config/pinepi.sudoers" /etc/sudoers.d/pinepi
visudo -cf /etc/sudoers.d/pinepi
install -o root -g root -m 0644 "${PROJECT_DIR}/config/pinepi.service" /etc/systemd/system/pinepi.service
systemctl daemon-reload
systemctl enable --now pinepi.service

echo "PinePi installed. Open http://$(hostname -I | awk '{print $1}'):8000"

