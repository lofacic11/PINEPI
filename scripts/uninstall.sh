#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this uninstaller as root: sudo ./scripts/uninstall.sh [--purge-data]" >&2
  exit 1
fi

systemctl disable --now pinepi.service pinepi-management-ap.service 2>/dev/null || true
/usr/local/sbin/pinepi-helper management-stop >/dev/null 2>&1 || true
/usr/local/sbin/pinepi-helper ap-stop >/dev/null 2>&1 || true
/usr/local/sbin/pinepi-helper scan-stop >/dev/null 2>&1 || true
/usr/local/sbin/pinepi-helper capture-stop >/dev/null 2>&1 || true
/usr/local/sbin/pinepi-helper active-stop >/dev/null 2>&1 || true
/usr/local/sbin/pinepi-helper monitor-disable >/dev/null 2>&1 || true
rm -f /etc/systemd/system/pinepi.service /etc/systemd/system/pinepi-management-ap.service /etc/sudoers.d/pinepi /usr/local/sbin/pinepi-helper
rm -rf /opt/pinepi
systemctl daemon-reload

if [[ ${1:-} == "--purge-data" ]]; then
  echo "Purging /etc/pinepi and /var/lib/pinepi as explicitly requested."
  rm -rf /etc/pinepi /var/lib/pinepi
  userdel pinepi 2>/dev/null || true
else
  echo "PinePi removed. Configuration and captures were preserved. Use --purge-data to delete them."
fi
