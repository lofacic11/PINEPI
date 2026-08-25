# PinePi

PinePi is a low-cost Raspberry Pi WLAN audit and security-training appliance for authorized school and lab use. It provides passive WLAN discovery, conservative security scoring, passive packet capture, and a configurable WPA2 Training AP with normal Internet forwarding. It deliberately excludes credential harvesting, HTTPS interception, deauthentication, forced reconnects, replay attacks, and automated password cracking.

## Architecture

The web application never runs as root. FastAPI handles validation, state, presentation, and cached status reads. A small root helper exposes only enumerated operations and validates every value again before invoking Linux networking tools without a shell.

```text
Browser (desktop/mobile)
          |
       FastAPI                 unprivileged pinepi user
          |
   fixed helper actions        sudo; JSON password over stdin
          |
 iw / airodump / dumpcap / hostapd / dnsmasq / nftables
          |
  management | audit adapter | Training AP adapter
```

The helper tracks process IDs under `/run/pinepi`, verifies the expected executable through `/proc`, rejects duplicate processes, notices stale processes, and applies timeouts at the web/helper boundary. Scan and capture files live under `/var/lib/pinepi`, never `/tmp`.

## Network topology

```text
phone/laptop                 authorized training clients
     |                                  |
Management Wi-Fi                     RT5572
     |                           Training AP 10.42.0.1
internal Raspberry Pi WLAN                 |
10.43.0.1                                  +-- PinePi NAT -- eth0 -- Internet
     |
PinePi UI http://10.43.0.1:8000

RTL8814AU (0bda:8813) -> monitor mode, scan, and passive capture
```

The internal non-USB WLAN is reserved for permanent management access. It starts at boot and does not provide Internet forwarding. The RT5572 remains the Training AP, while the RTL8814AU remains the audit adapter. Training NAT excludes all three Wi-Fi role interfaces and uses an eligible default uplink such as `eth0`; without one, the Training AP still provides DHCP and local PinePi access with forwarding shown as disabled.

## Adapter roles

PinePi does not assume `wlan1` and `wlan2` are stable. At runtime it inspects:

- configured management interface names;
- sysfs driver, MAC address, and parent USB vendor/product IDs;
- `iw phy` AP and monitor-mode capabilities.

Internal WLAN detection prefers a non-USB `brcmfmac`/platform/MMC device rather than assuming it is always `wlan0`. Interface names remain configurable fallbacks.

The default mapping prefers `0bda:8813` (RTL8814AU/AWUS1900 class) for audit/monitor use and `148f:5572` (RT5572) for the Training AP. Capability-based fallback is used when a preferred ID is absent. The Dashboard shows the resulting role and reason. Operations return a readable error if the required adapter is missing.

Edit `/etc/pinepi/pinepi.toml` to add another USB ID. A stable per-device MAC rule can be added to the detector later without changing API or UI code.

## Features

- Responsive dark dashboard with CPU, RAM, root-storage usage, uptime, adapter mode, connection, channel, and TX power.
- Boot-managed WPA2 management network with status, client count, and a stable local UI address.
- Passive `airodump-ng` scan with structured access-point data and backend target selection.
- Modular passive rating (`app/services/audit.py`) with deliberately limited claims.
- Channel-locked `dumpcap` PCAPNG capture, frozen stop time, live packet/size/EAPOL counts, safe download/delete, and a configured file-size stop condition.
- EAPOL wording remains an indicator: 0 is “Not detected,” 1–3 is “EAPOL detected,” and 4+ is “Likely complete.” It is not M1/M2/M3/M4 validation.
- WPA2 Training AP with DHCP/DNS, client enumeration, dynamic default IPv4 uplink selection, and scoped nftables forwarding/NAT.

## Training AP networking

The default AP is `10.42.0.1/24`, with DHCP leases from `10.42.0.20` to `10.42.0.200`. The helper discovers the current default IPv4 route and rejects the AP interface itself as an uplink. Its dedicated `ip pinepi` nftables table allows AP-to-uplink forwarding, established return traffic, and masquerading only through that chosen uplink. The table is removed when the AP stops. The previous `net.ipv4.ip_forward` value is restored.

Connected clients can browse to `http://10.42.0.1:8000`. There is no credential portal.

## Raspberry Pi installation

Use a current Debian/Raspberry Pi OS installation and verify that both USB adapters have drivers supporting the required mode. Then:

```bash
git clone <your-repository> pinepi
cd pinepi
sudo ./scripts/install.sh
```

The installer adds OS dependencies, creates the non-login `pinepi` service user, installs the app in `/opt/pinepi`, installs the root-owned helper and restricted sudo rule, creates persistent storage, and enables `pinepi.service`. Open `http://<raspberry-pi-ip>:8000`.

The installer disables the distribution-wide `dnsmasq.service` and `hostapd.service`; PinePi runs dedicated, interface-bound instances instead. Management and Training use separate configs, PID files, lease files, state, and logs under `/run/pinepi/management` and `/run/pinepi/training`.

`/run` is ephemeral and is cleared at boot. The systemd unit creates `/run/pinepi` with `RuntimeDirectory=pinepi` before applying its `ReadWritePaths` sandbox. This keeps runtime PID/config/state files temporary and prevents `status=226/NAMESPACE` failures without weakening `ProtectSystem` or the other service hardening.

Review `config/pinepi.example.toml` before deployment, especially the country code, adapter IDs, and capture limit. Channels 12–13 depend on the adapter, driver, and regulatory domain. Use a unique lab password; the example password is only a development default and is never returned by an API.

Change the example `[management_ap]` password before exposing the appliance. Management defaults to `10.43.0.1/24`, deliberately separate from Training AP subnet `10.42.0.0/24`.

Useful commands:

```bash
sudo systemctl status pinepi
sudo journalctl -u pinepi -f
sudo systemctl restart pinepi
```

The service uses a read-only system view, a private temporary directory, and only the necessary writable runtime/data paths. `NoNewPrivileges` cannot be enabled because it would disable the restricted sudo transition; privilege is instead constrained to the root-owned helper named in `/etc/sudoers.d/pinepi`. The helper is not writable by the service user and has no arbitrary-command action.

## Development

Python 3.11 or newer is required because configuration uses the standard-library TOML reader.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The dashboard and `/health` work without root. Hardware actions intentionally fail with a clear error unless the helper and Wi-Fi tools are installed. For device testing, use the normal installer; do not run Uvicorn as root.

## Monitor mode and coexistence

Monitor mode receives raw 802.11 frames and disconnects that interface from ordinary managed Wi-Fi. PinePi therefore reserves a dedicated adapter for scan/capture and leaves the management uplink separate. Scan and capture are mutually exclusive because both own the audit adapter. Starting a capture locks it to the selected target channel. Clean FastAPI shutdown stops transient scan/capture operations so capture files remain valid; the Training AP is left under explicit Start/Stop control.

## Storage protection

Each new scan removes the previous `current*` scan artifacts before launching `airodump-ng`. Captures use dumpcap's file-size autostop and remain on disk if the limit is reached. Status then reports `size limit reached`. Adjust `max_capture_mb` to suit the SD card. Uninstall preserves `/var/lib/pinepi` unless `--purge-data` is explicitly passed.

## Project layout

```text
app/
  api/                 FastAPI route modules
  models/              request/response validation models
  services/            adapter, scan, capture, AP, and process logic
  static/ and templates/
scripts/
  pinepi-helper        restricted privileged boundary
  install.sh, uninstall.sh
config/                example TOML, systemd unit, sudo policy
tests/                 parser, scoring, config, and path-safety tests
```

## Security model and limitations

This project is suitable only for networks you own or have explicit permission to test. WLAN discovery and packet capture can still be regulated by local law.

- Authentication for the web UI is not yet implemented. Bind it only to a trusted management network and add authentication/TLS before multi-user deployment.
- The selected target is in memory and is lost when FastAPI restarts.
- Security scores use advertised encryption only; they do not assess password strength, router patches, WPS, segmentation, or application-layer security.
- Four EAPOL frames do not prove a usable handshake. Proper station/BSSID correlation, replay-counter checks, and M1–M4 sequence validation remain future work.
- Adapter mode support reported by `iw` does not guarantee a particular driver is reliable under load.
- Status packet/EAPOL analysis reads the current capture with `capinfos`/`tshark` and is cached. Very large captures can still make this slower; a future capture-side counter should replace repeated reads.
- AP startup currently assumes no other hostapd/dnsmasq instance owns the selected AP interface/address. NetworkManager or `dhcpcd` may need an unmanaged-interface rule for USB audit/AP devices.
- Application state and audit history are not persistent; SQLite is the intended next step.

## Troubleshooting

**No adapter role:** run `lsusb`, `iw dev`, and `iw phy`. Add the observed USB ID to the config and confirm the driver advertises monitor/AP mode.

**Monitor mode fails:** stop software managing that USB interface (often NetworkManager or `wpa_supplicant`) and confirm the out-of-tree RTL8814AU driver matches the running kernel.

**hostapd fails:** inspect `journalctl -u pinepi`, test a channel allowed by the configured country, and verify AP support with `iw phy <phy> info`.

**Clients have no Internet:** confirm `ip -4 route show default`, `sysctl net.ipv4.ip_forward`, and `sudo nft list table ip pinepi`. The default route must not point through the Training AP interface.

**Capture remains at zero:** check `dumpcap -D`, interface permissions/driver state, free space with `df -h /var/lib/pinepi`, and whether the selected channel is correct.

**Web API reports sudo failure:** validate the installed policy with `sudo visudo -cf /etc/sudoers.d/pinepi` and ensure `/usr/local/sbin/pinepi-helper` is root-owned and not writable by `pinepi`.

**dnsmasq failed to start:** PinePi now returns the daemon's actual startup reason and retains its runtime log under `/run/pinepi/<management|training>/dnsmasq.log`. Check `journalctl -u pinepi-management-ap.service -n 50`, `ss -lntup`, `ps aux | grep '[d]nsmasq'`, `ip addr`, and `iw dev`. A distribution or NetworkManager dnsmasq bound to all addresses must be disabled; PinePi instances bind only their assigned interface/gateway and use separate PID and lease files.

**Management network is stopped:** check `systemctl status pinepi-management-ap.service` and its journal. Confirm the internal adapter appears in `iw dev`, uses `brcmfmac` or another configured management driver, and is not blocked by rfkill. Management AP failure does not prevent the PinePi web service from starting on other available interfaces.

## Planned extensions

The service boundaries support rogue/duplicate SSID detection, channel analytics, frame-type and packets-per-second counters, proper WPA message validation, SQLite audit history, JSON/CSV/PDF reports, and a clearly labelled dummy-credential training portal. None requires broadening the helper into arbitrary command execution.
