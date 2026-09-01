#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo ./scripts/install.sh" >&2
  exit 1
fi

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive

apt-get update
REQUIRED_PACKAGES=(python3 python3-venv iw aircrack-ng tshark wireshark-common hostapd dnsmasq nftables sudo)
apt-get install -y "${REQUIRED_PACKAGES[@]}"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  echo "Detected distribution: ${PRETTY_NAME:-${ID:-unknown} ${VERSION_ID:-}}"
fi

# These engines are registered dynamically and remain optional because Debian
# and Raspberry Pi OS package availability differs by release and architecture.
OPTIONAL_PACKAGES=(kismet hcxdumptool hcxtools python3-scapy mdk4 suricata zeek bettercap)
for package in "${OPTIONAL_PACKAGES[@]}"; do
  if apt-cache show "$package" >/dev/null 2>&1; then
    apt-get install -y "$package" || echo "Warning: optional module package '$package' could not be installed." >&2
  else
    echo "Optional module package '$package' is not available from configured repositories." >&2
  fi
done
# Optional offline vendor names. Recon remains functional with Unknown vendors if unavailable.
apt-get install -y ieee-data || echo "Warning: optional ieee-data OUI dataset is unavailable." >&2

# PinePi runs isolated hostapd/dnsmasq processes per AP. Distribution-wide
# daemons would compete for interfaces, DNS port 53, and DHCP port 67.
systemctl disable --now dnsmasq.service >/dev/null 2>&1 || true
systemctl disable --now hostapd.service >/dev/null 2>&1 || true

if ! id pinepi >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pinepi --create-home --shell /usr/sbin/nologin pinepi
fi

install -d -o root -g root -m 0755 /opt/pinepi /etc/pinepi
install -d -o root -g pinepi -m 0750 \
  /var/lib/pinepi \
  /var/lib/pinepi/scans \
  /var/lib/pinepi/captures
install -d -o pinepi -g pinepi -m 0750 /var/lib/pinepi/data
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
install -o root -g root -m 0644 "${PROJECT_DIR}/config/pinepi-management-ap.service" /etc/systemd/system/pinepi-management-ap.service
systemctl daemon-reload
systemctl enable pinepi-management-ap.service pinepi.service
if ! systemctl restart pinepi-management-ap.service; then
  echo "Warning: Management AP did not start; PinePi web service will still be started." >&2
  echo "Check: journalctl -u pinepi-management-ap.service -n 50" >&2
fi
systemctl restart pinepi.service

echo "Detected PinePi tool engines:"
for tool in aircrack-ng airmon-ng airodump-ng aireplay-ng airdecap-ng dumpcap tshark kismet hcxdumptool hcxpcapngtool mdk4 bettercap suricata zeek; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  READY   $tool"
  else
    echo "  MISSING $tool (optional unless documented as core)"
  fi
done

echo "PinePi installed. Open http://$(hostname -I | awk '{print $1}'):8000"
