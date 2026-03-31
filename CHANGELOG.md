# Changelog

All notable changes to airohunt-ng will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2025-01-01

### Added
- Initial release
- Real-time three-pane scanner: Access Points, Connected Clients, Probe Requests
- Signal strength graph with threshold line and rolling statistics
- Accurate encryption detection from raw beacon IE parsing (OPN/WEP/WPA/WPA2-PSK/WPA2-EAP/WPA3-SAE/WPA3-OWE/WPA2/3)
- 2.4 GHz and 5 GHz band support (`--band`)
- Single-channel lock (`-c`)
- Direct-to-graph mode (`--bssid` + `-c`)
- Pane selection flags (`-A`, `-C`, `-P`)
- Per-pane independent scrolling with `j`/`k`
- Pause/resume scanning with `Space`
