# PinePi — multi-engine development branch (v0.9.0 baseline)

PinePi is a low-cost Raspberry Pi WLAN audit and security-training appliance for networks owned by the operator, authorized penetration tests, isolated labs, and classroom demonstrations. This development branch builds on the v0.9.0 Web UI Foundation with a real capability registry, bounded offline analysis, explainable rogue indicators, and deliberately targeted active WLAN diagnostics. It still excludes credential harvesting, HTTPS interception, generic packet injection, arbitrary replay commands, indiscriminate disruption, and automated password cracking.

## Architecture

The web application never runs as root. FastAPI handles validation, state, presentation, and cached status reads. A small root helper exposes only enumerated operations and validates every value again before invoking Linux networking tools without a shell.

```text
Browser (desktop/mobile)
          |
       FastAPI                 unprivileged pinepi user
          |
   fixed helper actions        sudo; JSON password over stdin
          |
 iw / Aircrack / dumpcap / tshark / HCX / optional analysis engines
          |
  management | audit adapter | Training AP adapter
```

The helper tracks process IDs under `/run/pinepi`, verifies the expected executable through `/proc`, rejects duplicate processes, notices stale processes, and applies timeouts at the web/helper boundary. A central application operation manager persists ownership, status, PIDs, structured failures, and recent history in SQLite. Stale operations are reconciled at startup. Persistent state lives under `/var/lib/pinepi`; ephemeral process state lives under `/run/pinepi`, never `/tmp`.

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

- Responsive, keyboard-accessible application shell for phones, tablets, and desktops. Its collapsible desktop sidebar becomes a full mobile drawer and organizes Dashboard, Campaigns/Audits, Access Point, Recon, Logging, Modules, Captures, Wireless Tools, Security Analysis, Packet Capture, Diagnostics/Console, Reports, and Settings.
- Guided Mode (default) uses plain-language signal and security explanations; locally persisted Expert Mode reveals BSSID, frequency, timestamps, raw advertised flags, packet counts, interfaces, and diagnostics—but never a command shell.
- Real Dashboard state for version, hostname, CPU, temperature, storage, uptime, time, adapter roles, management network, active/recent operations, and Recon summary.
- Boot-managed WPA2 management network with status, client count, and a stable local UI address.
- Explicit passive Recon sessions with durable SQLite AP/client observations, search, server-side filters/sorting, bounded pagination, details, reopen/delete, and configurable retention.
- PinePi-branded Recon workspace with Scanning/Handshakes tabs, real wireless-object and channel-distribution summaries, previous-session metadata, AP/client tables, and responsive details drawers. Channel distribution is observed AP count, never spectrum utilization or airtime.
- AP/client relationship details, bounded signal samples, MAC-randomization warnings, offline vendor lookup, and conservative trusted-profile indicators.
- Channel occupancy estimates based on observed nearby networks, overlap counts for 2.4 GHz, and a basic owned-AP channel recommendation. These are not airtime or spectrum-analyser measurements.
- Modular passive rating (`app/services/audit.py`) with deliberately limited claims.
- Channel-locked `dumpcap` PCAPNG capture, frozen stop time, live packet/size/EAPOL counts, safe download/delete, and a configured file-size stop condition.
- EAPOL wording remains an indicator: 0 is “Not detected,” 1–3 is “EAPOL detected,” and 4+ is “Likely complete.” It is not M1/M2/M3/M4 validation.
- WPA2 Training AP with DHCP/DNS, client enumeration, dynamic default IPv4 uplink selection, and scoped nftables forwarding/NAT.
- Read-only bounded logging for an exact allowlist of PinePi application, management, hostapd, dnsmasq, Recon, and capture sources. Diagnostics expose registered status data only; there is no browser shell or arbitrary file reader.
- Cached capability detection for individual Aircrack-ng utilities, Wireshark, Kismet, HCX, Scapy, MDK4, Bettercap, Suricata, and Zeek, including version, privilege, adapter, and active/passive metadata.
- Explicitly selected, acknowledged, management-network-only Aircrack injection diagnostics and bounded targeted deauthentication tests. MDK4 exposes one similarly bounded BSSID-targeted advanced test when installed. Every active operation owns the audit adapter and has a visible Stop action.
- Bounded tshark capture statistics, HCX WPA/PMKID validation, Aircrack compatibility inspection, Scapy header/IE exploration, Suricata offline alerts, and Zeek offline summaries. Capture paths always pass through the existing PCAPNG resolver.
- Explainable weighted rogue/duplicate-SSID indicators and bounded JSON session reports that distinguish observations, calculated indicators, and operator-run active tests.

## Engine support matrix

Third-party tools are engines behind typed PinePi services; none is exposed as a command textbox.

| Tool | PinePi role | Required | Classification | Current integration |
|---|---|---:|---|---|
| Aircrack-ng suite | Recon, capability/injection diagnostics, targeted authorized test, offline compatibility | Core | Mixed | Individual binary/version detection; airodump Recon; aireplay injection and bounded targeted deauthentication; offline metadata summary |
| Wireshark dumpcap/tshark | Capture and cached protocol/frame statistics | Core | Passive | Existing bounded PCAPNG capture plus one-pass bounded analysis |
| Kismet | Alternative Recon source | Optional | Passive | Binary/version/status and normalization adapter; live API ingestion still requires future source/auth configuration |
| hcxdumptool | Advanced capture capability | Optional | Mixed | Detected and classified; capture execution is intentionally not enabled until version-specific passive/active flags can be enforced |
| hcxpcapngtool | WPA/EAPOL/PMKID validation | Optional | Passive/offline | Temporary HC22000 conversion; only aggregate validation counts are returned, never hash material |
| Scapy | Educational 802.11 frame explorer | Optional | Passive/offline | Bounded headers and information elements; application payloads are excluded |
| MDK4 | Advanced authorized test | Optional | Active | One BSSID-targeted, kernel-channel-constrained, timeout-bounded mode; no arbitrary arguments |
| Bettercap | Future discovery source | Optional | Mixed | Availability/version registry only; arbitrary caplets and commands are not exposed |
| Suricata | Defensive PCAP IDS | Optional | Passive/offline | Temporary offline run with bounded, field-whitelisted alerts |
| Zeek | Defensive traffic summary | Optional | Passive/offline | Temporary offline run with bounded known log types and whitelisted fields |

Legacy Aircrack utilities are detected individually and remain visible under the Aircrack-ng capability group. Utilities without a dedicated PinePi model are detection-only; their command-line interfaces are not passed through to the browser.

## Passive and active operation model

Recon, PCAPNG capture, offline analysis, channel observations, and anomaly scoring are passive. Injection diagnostics, aireplay-ng deauthentication, and the supported MDK4 mode are active and can disrupt connectivity.

An active request is accepted only when all of the following hold:

1. an AP has been explicitly selected from Recon;
2. the submitted BSSID and channel still match that selection;
3. the operator checks the authorization acknowledgement and accepts a target-specific confirmation dialog;
4. the direct HTTP peer is in the configured Management subnet or is loopback—`X-Forwarded-For` is ignored;
5. the request carries PinePi's non-simple confirmation header, preventing ordinary cross-site form submission;
6. the backend operation manager grants exclusive ownership of the audit adapter;
7. the helper independently validates interface, channel, BSSID, optional client, burst count, runtime, and operation type.

There is no “all nearby networks” mode. The helper wraps long-running active engines with a hard timeout, verifies the expected executable through `/proc`, captures bounded logs, provides Stop with TERM/KILL fallback, and restores managed mode after stop, failure, timeout, or observed process exit. PinePi reports `airmon-ng check` output but never automatically kills unrelated processes.

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

The installer treats Python, `iw`, Aircrack-ng, tshark/Wireshark, hostapd, dnsmasq, nftables, and sudo as required. It checks the configured Debian/Raspberry Pi OS repositories for Kismet, hcxdumptool, hcxtools, `python3-scapy`, MDK4, Suricata, Zeek, and Bettercap individually. A missing optional package produces a warning rather than aborting installation. It does not use `curl | bash`, add third-party repositories, or compile unpinned external projects. After installation it prints a per-binary READY/MISSING summary; the Modules page performs the authoritative runtime check.

The installer disables the distribution-wide `dnsmasq.service` and `hostapd.service`; PinePi runs dedicated, interface-bound instances instead. Management and Training use separate configs, PID files, lease files, state, and logs under `/run/pinepi/management` and `/run/pinepi/training`.

`/run` is ephemeral and is cleared at boot. The systemd unit creates `/run/pinepi` with `RuntimeDirectory=pinepi` before applying its `ReadWritePaths` sandbox. This keeps runtime PID/config/state files temporary and prevents `status=226/NAMESPACE` failures without weakening `ProtectSystem` or the other service hardening.

Review `config/pinepi.example.toml` before deployment, especially the country code, adapter IDs, capture limit, and `CHANGE-ME-BEFORE-USE` placeholders. Channels 12–13 depend on the adapter, driver, and regulatory domain. General status, settings, operation, health, and logging APIs never return passwords.

The one deliberate exception is `GET /api/training-ap/credentials`: while a PinePi-owned Training/Lab AP is running, it returns only that AP's active SSID, channel, and PSK so the Access Point page can keep the Lab password visible and copyable. The route accepts the direct TCP peer only from the configured Management subnet (or loopback for local development), does not trust `X-Forwarded-For`, and reads the root-owned active hostapd configuration through the restricted helper. It never returns a Management Wi-Fi password, system password, scanned-network password, or captured credential. PinePi does not know or recover an observed network's original WPA password; a same-SSID Lab AP always uses a new PinePi-controlled PSK.

Change the example `[management_ap]` password before exposing the appliance. Management defaults to `10.43.0.1/24`, deliberately separate from Training AP subnet `10.42.0.0/24`.

### First boot and updates

After installation, connect a phone or laptop to the configured Management Wi-Fi and open `http://10.43.0.1:8000`. Open **Recon**, press **Start Scan**, inspect or select an AP, then press **Stop Scan**; completed sessions remain available after restart. Selecting an AP can prefill an authorized same-SSID Lab AP or a channel-locked passive capture. The displayed Lab password is explicitly a new PinePi-controlled password and its Copy button includes a selection-based fallback for the normal HTTP management origin. No terminal is needed for normal use.

To update an installed checkout on the Raspberry Pi:

```bash
cd /path/to/PINEPI
git pull --ff-only origin main
sudo ./scripts/install.sh
sudo systemctl status pinepi pinepi-management-ap
```

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

The helper also restores the audit adapter to managed mode if scanner/capture startup fails or a tracked process exits unexpectedly. Training AP startup is transactional: hostapd, dnsmasq, PinePi's dedicated `table ip pinepi`, the owned interface address, and the prior `net.ipv4.ip_forward` value are rolled back after partial failure. Stop and identical repeated start requests are idempotent; different settings require an explicit stop first. Startup reconciliation reclaims operation ownership for validated live scanner, capture, and Training AP processes after a FastAPI restart.

Wireless Tools can explicitly enable/disable native `iw` monitor mode without relying on airmon-generated interface names. The UI shows PHY, driver, USB ID, current mode/channel, AP/monitor support, and supported, disabled, no-IR, and DFS channel lists reported by the kernel. PinePi never bypasses the kernel regulatory domain.

## Capture analysis

Opening a capture never automatically parses an unbounded file. `[analysis]` limits input size, packet count, and returned rows. Only filenames accepted by the existing PCAPNG safe-path resolver can be analyzed; absolute paths, traversal, alternate extensions, missing files, and resolved paths outside the capture root are rejected.

- tshark performs one bounded field pass for management/control/data totals, management subtypes, EAPOL, ARP, DHCP, DNS, TCP, UDP, TLS, BSSIDs, and stations.
- hcxpcapngtool writes into a private temporary directory. PinePi counts `WPA*01` PMKID and `WPA*02` EAPOL-pair records, then deletes the temporary material without returning hashes.
- Aircrack-ng receives an explicitly selected local capture with closed stdin and a 30-second timeout. The result is compatibility metadata only; wordlist/password auditing is not implemented.
- Scapy returns at most 200 requested frame headers per page and stops at the configured packet limit. It exposes 802.11 addressing, type/subtype, sequence, and bounded information elements, not application payloads.
- Suricata and Zeek run offline in private temporary output directories. Only known, whitelisted fields are returned and row counts are capped.

Capture metadata—engine, selected SSID/BSSID, channel, operation, and creation time—is persisted separately from the file. It does not contain keys or credentials.

## Storage protection

SQLite history is stored at `/var/lib/pinepi/data/pinepi.db`; scanner artifacts are in `/var/lib/pinepi/scans`; captures are in `/var/lib/pinepi/captures`. Session age/count and per-AP signal samples are bounded by `[recon]` settings, and the UI supports session or full-history deletion with confirmation. Each new scan removes the previous `current*` runtime scanner artifacts before launching `airodump-ng`. Captures use dumpcap's file-size autostop and remain on disk if the limit is reached. Uninstall preserves `/var/lib/pinepi` unless `--purge-data` is explicitly passed.

## Offline vendor data

PinePi looks for the system-provided IEEE OUI text file at `/usr/share/ieee-data/oui.txt` and then `/usr/share/misc/oui.txt`. Scanning continues with `Unknown` if neither exists. Install or update the Debian `ieee-data` package with `sudo apt update && sudo apt install ieee-data`; consult that package and the IEEE Registration Authority terms for dataset licensing and redistribution obligations. Locally administered addresses are labelled `Randomized/local address`, not assigned a potentially misleading vendor.

## Development and mock Recon

Set `mock_mode = true` under `[recon]` only in a development configuration. The UI displays a prominent **SIMULATED** banner and production never falls back automatically. `mock_scenario` accepts `normal`, `empty`, `failure`, or `missing_adapter`; normal mode includes deterministic 2.4/5 GHz, hidden, open/WPA2/WPA3, associated/unassociated, randomized-MAC, changing-signal, and trusted-profile indicator fixtures.

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
- Active and monitor-mode APIs add direct Management-subnet enforcement and a cross-site-form-resistant confirmation header, but this is not user authentication. Any client admitted to the Management Wi-Fi must still be treated as an authorized appliance operator.
- The visible Lab PSK is intentionally available to every client on the trusted Management subnet while the PinePi-owned AP is running. Network isolation is therefore part of the current access-control model; the route is not a substitute for future UI authentication.
- The selected future-audit target is in memory and is lost when FastAPI restarts; Recon history itself is persistent.
- Security scores use advertised encryption only; they do not assess password strength, router patches, WPS, segmentation, or application-layer security.
- Four EAPOL frames do not prove a usable handshake. Proper station/BSSID correlation, replay-counter checks, and M1–M4 sequence validation remain future work.
- Adapter mode support reported by `iw` does not guarantee a particular driver is reliable under load.
- Status packet/EAPOL analysis reads the current capture with `capinfos`/`tshark` and is cached. Very large captures can still make this slower; a future capture-side counter should replace repeated reads.
- AP startup currently assumes no other hostapd/dnsmasq instance owns the selected AP interface/address. NetworkManager or `dhcpcd` may need an unmanaged-interface rule for USB audit/AP devices.
- Recon sees advertised metadata, not packet payloads. SSID equality and trusted-profile differences are investigation indicators, never proof that an AP is malicious.
- Client MACs can be randomized and should not be treated as durable physical-device identities. Previously observed clients are scoped to their selected scan session.
- Channel counts come from observed beacon/network data and do not measure utilization, interference, or airtime.
- Kismet binary/device normalization exists, but live Kismet API authentication and ingestion are not enabled. Choosing `recon.engine="kismet"` fails clearly instead of silently falling back; `auto` deterministically uses PinePi/airodump today.
- hcxdumptool is detected but not launched because its active/passive behavior and flags vary by packaged version. hcxpcapngtool offline validation is implemented.
- Bettercap is detection-only. Generic caplets, commands, and browser terminals are intentionally unavailable.
- The MDK4 integration is limited to a timeout-bounded selected-BSSID mode. Other MDK4 and legacy Aircrack test modes require separate typed threat/safety models before exposure.
- Offline password auditing, airdecap key processing, airolib databases, arbitrary wordlists, and discovered-key display are not implemented. No candidate keys are transmitted or logged.
- Suricata and Zeek results are returned on demand and are not yet persisted as report artifacts. Report file export (PDF/CSV) remains future work.

## Troubleshooting

**No adapter role:** run `lsusb`, `iw dev`, and `iw phy`. Add the observed USB ID to the config and confirm the driver advertises monitor/AP mode.

**Monitor mode fails:** stop software managing that USB interface (often NetworkManager or `wpa_supplicant`) and confirm the out-of-tree RTL8814AU driver matches the running kernel.

**hostapd fails:** inspect `journalctl -u pinepi`, test a channel allowed by the configured country, and verify AP support with `iw phy <phy> info`.

**Clients have no Internet:** confirm `ip -4 route show default`, `sysctl net.ipv4.ip_forward`, and `sudo nft list table ip pinepi`. The default route must not point through the Training AP interface.

**Capture remains at zero:** check `dumpcap -D`, interface permissions/driver state, free space with `df -h /var/lib/pinepi`, and whether the selected channel is correct.

**Lab password is unavailable:** access PinePi through the configured Management subnet, not the Training subnet or another routed interface. The credential endpoint intentionally uses the direct connection address and ignores forwarded-client headers. Confirm both Training hostapd and dnsmasq are still running.

**A scan/capture process exited:** open **Logging** and select Recon scanner or Packet capture. Output is limited to the newest 80 lines/16 KiB and credential-like values are redacted. PinePi restores the audit interface to managed mode when it observes the exit; confirm this with `iw dev` before restarting the operation.

**An active test is unavailable:** connect through the Management Wi-Fi, select the AP in Recon again, confirm the BSSID/channel, and check authorization. Open Modules to confirm aireplay-ng or MDK4 is installed, then use Adapter Diagnostics to inspect monitor support and `airmon-ng check` conflicts. PinePi does not automatically kill NetworkManager or wpa_supplicant.

**Offline analysis says TOOL_MISSING:** install the corresponding optional distribution package and press **Refresh detection** in Modules. For Zeek and Bettercap, package availability varies substantially by Debian release; do not add untrusted repositories merely to satisfy an optional module.

**CHANNEL_UNSUPPORTED or regulatory failure:** inspect the Wireless Tools PHY channel lists and `iw reg get`. Disabled and no-IR channels cannot be made transmissive through PinePi. Set the correct country in `pinepi.toml` and use a channel supported by the adapter, driver, and kernel domain.

**Web API reports sudo failure:** validate the installed policy with `sudo visudo -cf /etc/sudoers.d/pinepi` and ensure `/usr/local/sbin/pinepi-helper` is root-owned and not writable by `pinepi`.

**dnsmasq failed to start:** PinePi now returns the daemon's actual startup reason and retains its runtime log under `/run/pinepi/<management|training>/dnsmasq.log`. Check `journalctl -u pinepi-management-ap.service -n 50`, `ss -lntup`, `ps aux | grep '[d]nsmasq'`, `ip addr`, and `iw dev`. A distribution or NetworkManager dnsmasq bound to all addresses must be disabled; PinePi instances bind only their assigned interface/gateway and use separate PID and lease files.

**Management network is stopped:** check `systemctl status pinepi-management-ap.service` and its journal. Confirm the internal adapter appears in `iw dev`, uses `brcmfmac` or another configured management driver, and is not blocked by rfkill. Management AP failure does not prevent the PinePi web service from starting on other available interfaces.

## Planned extensions

Next work includes authenticated operator sessions/TLS, Kismet API ingestion, version-gated hcxdumptool modes, persistent IDS/Zeek result pagination, richer RSN information-element decoding, validated report exports, and carefully modeled additional legacy lab tests. None requires broadening the helper into arbitrary command execution.
