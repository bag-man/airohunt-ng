# airohunt-ng

> [!CAUTION]
> This software was almost entirely written by Claude.ai Sonnet 4.6

A terminal-based 802.11 Wi-Fi signal tracker for Linux that runs in monitor mode.

Displays access points, connected clients, and probe requests in a live three-pane
interface, and lets you select any device to track its signal strength over time on
a real-time graph.

![Scanner](screenshots/interface1.png)
![Tracker](screenshots/interface2.png)

## Requirements
- monitor mode capable wireless interface
- tcpdump
- iw
- Python 3.8+

## Installation

### pip (recommended)

```bash
pip install airohunt-ng
```

### Arch Linux (AUR)

```bash
yay -S airohunt-ng
# or
paru -S airohunt-ng
```

### From source

```bash
git clone https://github.com/YOURUSERNAME/airohunt-ng
cd airohunt-ng
pip install .
```

## Usage

First put your wireless interface into monitor mode:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

Then run:

```bash
sudo airohunt-ng wlan0
```

### Options

```
positional arguments:
  interface          Monitor-mode interface (e.g. wlan0)

options:
  --band {2.4,5,both}  Band to scan: 2.4 GHz (default), 5 GHz, or both
  -c CH, --channel CH  Lock to a single channel instead of hopping
  --bssid MAC          Go straight to the signal graph for this BSSID (requires -c)
  -A                   Show Access Points pane only
  -C                   Show Connected Clients pane only
  -P                   Show Probes pane only
```

Pane flags may be combined: `-AC` shows Access Points and Connected Clients.

### Key bindings

| Key | Action |
|-----|--------|
| `h` / `l` or `←` / `→` | Switch active pane |
| `j` / `k` or `↑` / `↓` | Scroll within pane |
| `Enter` | Open signal graph for selected device |
| `Space` | Pause / resume scanning |
| `r` | Clear all results |
| `q` | Quit |

**Inside the signal graph:**

| Key | Action |
|-----|--------|
| `Space` | Pause / resume |
| `r` | Reset graph history |
| `Esc` | Back to scanner |
| `q` | Quit |

## Encryption detection

Encryption is determined by parsing the raw beacon frame bytes (RSN and WPA IEs),
not just the verbose tcpdump output. The ENC column shows one of:

| Value | Meaning |
|-------|---------|
| `OPN` | Open network |
| `WEP` | WEP (Privacy bit set, no WPA/RSN IE) |
| `WPA` | WPA1 (vendor IE `00:50:f2:01`) |
| `WPA2-PSK` | WPA2 Personal (RSN IE, AKM type 2) |
| `WPA2-EAP` | WPA2 Enterprise (RSN IE, AKM type 1) |
| `WPA3-SAE` | WPA3 Personal (RSN IE, AKM type 8) |
| `WPA3-OWE` | WPA3 Enhanced Open (RSN IE, AKM type 18) |
| `WPA2/3` | Transition mode (both PSK and SAE advertised) |

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).
