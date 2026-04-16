"""
Usage:
    sudo airohunt-ng <interface> [options]

Interface must already be in monitor mode:
    sudo ip link set wlan0 down
    sudo iw dev wlan0 set type monitor
    sudo ip link set wlan0 up

Requires: tcpdump, iw (or iwconfig)
"""

import curses
import subprocess
import re
import sys
import time
import shutil
import threading
import queue
import os
from collections import deque
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────

CHANNELS        = []                   # populated at startup by get_channels()

DWELL_S         = 0.5                  # seconds to listen per channel
SAMPLE_INTERVAL = 0.1                  # graph: seconds averaged per plot point
RENDER_HZ       = 10                   # UI refresh rate

Y_MIN           = -95                  # graph dBm floor
Y_MAX           = -10                  # graph dBm ceiling
Y_LABEL_W       = 5                    # width of Y-axis label column
FUNCTIONAL_DBM  = -78                  # threshold line on graph

# ── Regex patterns (compiled once) ────────────────────────────────────────────

# RSSI appears on the radiotap header line, e.g. "-38dBm signal"
_RSSI = [
    re.compile(r"(-\d+)\s*dBm signal", re.I),
    re.compile(r"signal\s+([-\d]+)\s*dBm", re.I),
    re.compile(r"antenna signal:\s*([-\d]+)", re.I),
]
_ESSID      = re.compile(r"beacon \(([^)]+)\)", re.I)
_PROBE_SSID = re.compile(r"probe request \(([^)]*)\)", re.I)
_SA         = re.compile(r"\bsa:([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
_BSSID      = re.compile(r"\bbssid:([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
_CH         = re.compile(r"\bch:\s*(\d+)", re.I)
_TIMESTAMP  = re.compile(r"^\d{2}:\d{2}:\d{2}")
_HEXLINE    = re.compile(r"^\s+0x[0-9a-f]+:\s+([0-9a-f ]+)", re.I)
_REG_RULE   = re.compile(r"\((\d+)\s*-\s*(\d+)\s*@")

# ── Regulatory channel discovery ──────────────────────────────────────────────

# All standard 20 MHz primary channels in the 5 GHz band.
# Listed explicitly because channel spacing is irregular across UNII sub-bands:
# UNII-1/2/2C use multiples of 4 starting at 36, while UNII-3/4 start at 149
# which is ≡ 1 mod 4 — a stride-based range(36, 178, 4) misses them entirely.
_STANDARD_5G = [
    36,  40,  44,  48,                                   # UNII-1
    52,  56,  60,  64,                                   # UNII-2A
    100, 104, 108, 112, 116, 120, 124, 128,              # UNII-2C
    132, 136, 140, 144,                                  # UNII-2C (extended)
    149, 153, 157, 161, 165,                             # UNII-3
    169, 173, 177,                                       # UNII-4 (US/some regions)
]


def _channels_in_band(start_mhz, end_mhz):
    """
    Return standard 802.11 channels whose centre frequency falls within
    [start_mhz, end_mhz].

    2.4 GHz uses a bandwidth-aware check (centre ± 10 MHz must fit within the
    band) because the US regulatory boundary at 2472 MHz sits exactly at the
    centre of channel 13 — without the ± 10 check, channels 12 and 13 would
    be incorrectly included.

    5 GHz uses a centre-only check against the explicit standard channel list,
    because regulatory band edges don't always align with ± half-bandwidth
    boundaries (e.g. UNII-4 channel 169 at 5845 MHz sits within the
    5730–5850 rule, but 5845 + 10 = 5855 > 5850 would wrongly exclude it).
    """
    half = 10
    channels = []

    # 2.4 GHz: bandwidth-aware
    for ch in range(1, 15):
        centre = 2407 + ch * 5 if ch < 14 else 2484
        if centre - half >= start_mhz and centre + half <= end_mhz:
            channels.append(ch)

    # 5 GHz: centre-frequency check against known standard channels only
    for ch in _STANDARD_5G:
        centre = 5000 + ch * 5
        if start_mhz <= centre <= end_mhz:
            channels.append(ch)

    return channels


def get_channels(iface, band="2.4"):
    """
    Query the global regulatory domain via `iw reg get` and return the
    permitted channels for the requested band.

    The *global* entry is used intentionally rather than the per-PHY entry.
    Self-managed adapters (e.g. mt7921u) report `country 00` for their own
    PHY, which covers far more channels than actually permitted under the
    active country setting. The global entry reflects what the kernel has
    been told via `iw reg set` / CRDA and is what the driver enforces.

    Falls back to conservative worldwide-safe defaults if iw is unavailable
    or the domain returns no usable rules.
    """
    _FALLBACK_2G = list(range(1, 12))   # FCC minimum — safe worldwide
    _FALLBACK_5G = [36, 40, 44, 48, 149, 153, 157, 161, 165]

    reg_text = ""
    if shutil.which("iw"):
        try:
            out = subprocess.run(
                ["iw", "reg", "get"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            ).stdout
            # iw reg get may return multiple blocks: "global" then "phy#N".
            # Truncate at the first phy block so self-managed PHY entries
            # (which report country 00) don't override the global rules.
            phy_start = out.find("\nphy#")
            reg_text = out[:phy_start] if phy_start != -1 else out
        except Exception:
            pass

    channels_2g, channels_5g = [], []
    for m in _REG_RULE.finditer(reg_text):
        start, end = int(m.group(1)), int(m.group(2))
        if end >= 6000:         # skip 6 GHz and 60 GHz bands
            continue
        for ch in _channels_in_band(start, end):
            (channels_2g if ch <= 14 else channels_5g).append(ch)

    channels_2g = sorted(set(channels_2g)) or _FALLBACK_2G
    channels_5g = sorted(set(channels_5g)) or _FALLBACK_5G

    if band == "5":
        return channels_5g
    if band == "both":
        return channels_2g + channels_5g
    return channels_2g

class Network:
    """An access point discovered via beacon frames."""
    __slots__ = ("bssid", "essid", "channel", "rssi", "last_seen", "beacons", "enc")

    def __init__(self, bssid, essid, channel, rssi, enc="OPN"):
        self.bssid     = bssid
        self.essid     = essid
        self.channel   = channel
        self.rssi      = rssi
        self.enc       = enc
        self.last_seen = time.monotonic()
        self.beacons   = 1

    def update(self, rssi, essid=None, enc=None):
        # Rolling average (window = 5) keeps display stable
        w = min(self.beacons, 4)
        self.rssi      = (self.rssi * w + rssi) / (w + 1)
        self.last_seen = time.monotonic()
        self.beacons  += 1
        if essid and essid != "<hidden>" and (not self.essid or self.essid == "<hidden>"):
            self.essid = essid
        if enc:
            self.enc = enc


class Client:
    """A station sending ToDS data frames to an AP."""
    __slots__ = ("mac", "ap_bssid", "essid", "channel", "rssi", "last_seen", "count")

    def __init__(self, mac, ap_bssid, essid, channel, rssi):
        self.mac       = mac
        self.ap_bssid  = ap_bssid
        self.essid     = essid
        self.channel   = channel
        self.rssi      = rssi
        self.last_seen = time.monotonic()
        self.count     = 1

    def update(self, rssi, essid=None):
        w = min(self.count, 4)
        self.rssi      = (self.rssi * w + rssi) / (w + 1)
        self.last_seen = time.monotonic()
        self.count    += 1
        if essid and essid not in ("<hidden>", "<unknown>") \
                and self.essid in ("<unknown>", "<hidden>"):
            self.essid = essid


class Probe:
    """A station sending probe-request frames."""
    __slots__ = ("mac", "essid", "channel", "rssi", "last_seen", "count")

    def __init__(self, mac, essid, channel, rssi):
        self.mac       = mac
        self.essid     = essid      # "<wildcard>" for broadcast probes
        self.channel   = channel
        self.rssi      = rssi
        self.last_seen = time.monotonic()
        self.count     = 1

    def update(self, rssi, essid=None, channel=None):
        w = min(self.count, 4)
        self.rssi      = (self.rssi * w + rssi) / (w + 1)
        self.last_seen = time.monotonic()
        self.count    += 1
        if channel:
            self.channel = channel
        if essid and essid not in ("<wildcard>", "<hidden>") \
                and self.essid == "<wildcard>":
            self.essid = essid

# ── Hardware helpers ──────────────────────────────────────────────────────────

def set_channel(iface, ch):
    """Tune the monitor interface to the given channel."""
    if shutil.which("iw"):
        subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                       stderr=subprocess.DEVNULL)
    elif shutil.which("iwconfig"):
        subprocess.run(["iwconfig", iface, "channel", str(ch)],
                       stderr=subprocess.DEVNULL)


def check_monitor_mode(iface):
    """Return True if the interface is in monitor mode."""
    try:
        out = subprocess.run(["iw", "dev", iface, "info"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True).stdout
        return "type monitor" in out
    except FileNotFoundError:
        raise RuntimeError("'iw' not found — is wireless-tools installed?")

def _parse_encryption(lines):
    """
    Determine encryption type from the raw beacon frame bytes (tcpdump -xx).

    Returns one of: 'OPN', 'WEP', 'WPA', 'WPA2-PSK', 'WPA2-EAP',
                    'WPA3-SAE', 'WPA3-OWE', or 'WPA2/3'

    Method:
      1. Reassemble hex dump lines into a byte string.
      2. Skip the radiotap header (length at bytes [2:4]).
      3. Skip the 24-byte 802.11 MAC header.
      4. Read the 2-byte Capabilities field (privacy bit = bit 4).
      5. Walk Information Elements looking for:
           - Tag 48  (RSN IE)  → WPA2 or WPA3, decode AKM suite type
           - Tag 221 (Vendor)  → WPA1 if OUI is 00:50:f2:01
      6. Classify based on what was found.

    AKM suite types (RFC 4017 / IEEE 802.11-2020 Table 9-151):
      1 = 802.1X (Enterprise)
      2 = PSK
      8 = SAE (WPA3-Personal)
      18 = OWE (WPA3-Open)
    """
    # Collect hex bytes from all hex-dump lines in the block
    raw_hex = ""
    for line in lines:
        m = _HEXLINE.match(line)
        if m:
            raw_hex += m.group(1).replace(" ", "")
    if not raw_hex:
        return None

    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return None

    # Radiotap header length (little-endian u16 at offset 2)
    if len(raw) < 4:
        return None
    rtap_len = int.from_bytes(raw[2:4], 'little')

    # Beacon body: radiotap + 24-byte 802.11 MAC header + 12-byte fixed fields
    #   fixed fields = timestamp(8) + beacon interval(2) + capabilities(2)
    caps_offset = rtap_len + 24 + 8 + 2
    if len(raw) < caps_offset + 2:
        return None

    caps = int.from_bytes(raw[caps_offset:caps_offset + 2], 'little')
    privacy = bool(caps & 0x0010)

    # Walk IEs
    has_wpa1 = False
    rsn_akms  = []          # AKM suite types found in RSN IE

    pos = caps_offset + 2   # first IE starts here
    while pos + 2 <= len(raw):
        tag    = raw[pos]
        length = raw[pos + 1]
        if pos + 2 + length > len(raw):
            break
        val = raw[pos + 2: pos + 2 + length]

        if tag == 48 and length >= 10:
            # RSN IE: version(2) + group(4) + pairwise_count(2) + pairwise(n*4)
            #         + akm_count(2) + akm(n*4)
            pairwise_count = int.from_bytes(val[6:8], 'little')
            akm_offset = 8 + pairwise_count * 4
            if len(val) >= akm_offset + 2:
                akm_count = int.from_bytes(val[akm_offset: akm_offset + 2], 'little')
                for i in range(akm_count):
                    suite_offset = akm_offset + 2 + i * 4
                    if suite_offset + 4 <= len(val):
                        rsn_akms.append(val[suite_offset + 3])

        elif tag == 221 and length >= 4:
            # Vendor-specific: WPA1 uses OUI 00:50:f2, type 01
            if val[:4] == b'\x00\x50\xf2\x01':
                has_wpa1 = True

        pos += 2 + length

    # Classify
    if rsn_akms:
        has_sae        = 8  in rsn_akms
        has_owe        = 18 in rsn_akms
        has_psk        = 2  in rsn_akms
        has_enterprise = 1  in rsn_akms

        if has_owe:
            return "WPA3-OWE"
        if has_sae and has_psk:
            return "WPA2/3"      # transition mode
        if has_sae:
            return "WPA3-SAE"
        if has_enterprise:
            return "WPA2-EAP"
        return "WPA2-PSK"

    if has_wpa1:
        return "WPA"

    if privacy:
        return "WEP"

    return "OPN"


# ── Scanner ───────────────────────────────────────────────────────────────────

def _reader_thread(proc, q):
    """Push stdout lines into q; send None sentinel when done."""
    try:
        for line in proc.stdout:
            q.put(line)
    except Exception:
        pass
    finally:
        q.put(None)


def _parse_rssi(lines):
    """Extract RSSI from the first (radiotap header) line, fall back to rest."""
    for line in lines:
        for pat in _RSSI:
            m = pat.search(line)
            if m:
                return float(m.group(1))
    return None


class Scanner(threading.Thread):
    """
    Hops through CHANNELS, running a short tcpdump capture on each.
    Populates three tables: networks (APs), clients, probes.
    """

    def __init__(self, iface):
        super().__init__(daemon=True)
        self.iface           = iface
        self.current_channel = None
        self.paused          = False
        self._lock           = threading.Lock()
        self._nets           = {}   # bssid  -> Network
        self._clients        = {}   # mac    -> Client
        self._probes         = {}   # mac    -> Probe
        self._stop_evt       = threading.Event()

    # ── Packet parsers ────────────────────────────────────────────────────────

    def _handle_beacon(self, lines, text, rssi, card_ch):
        m     = _BSSID.search(text) or _SA.search(text)
        bssid = m.group(1).upper() if m else None
        if not bssid:
            return

        m     = _ESSID.search(text)
        essid = m.group(1).strip() if m and "\x00" not in m.group(1) else "<hidden>"

        enc = _parse_encryption(lines) or "OPN"

        ch = card_ch
        m  = _CH.search(text)
        if m:
            candidate = int(m.group(1))
            if 1 <= candidate <= 165:
                ch = candidate

        with self._lock:
            if bssid in self._nets:
                net = self._nets[bssid]
                if card_ch == net.channel:
                    net.update(rssi, essid, enc)
                else:
                    # Wrong channel — update metadata but not RSSI
                    if essid != "<hidden>" and (not net.essid or net.essid == "<hidden>"):
                        net.essid = essid
                    net.enc      = enc
                    net.beacons += 1
            else:
                self._nets[bssid] = Network(bssid, essid, ch, rssi, enc)

    def _handle_probe(self, lines, text, rssi, card_ch):
        bssid_m   = _BSSID.search(text)
        bssid_val = bssid_m.group(1).upper() if bssid_m else ""

        mac = None
        for m in _SA.finditer(text):
            c = m.group(1).upper()
            if c != "FF:FF:FF:FF:FF:FF" and c != bssid_val:
                mac = c
                break
        if not mac:
            return

        m     = _PROBE_SSID.search(text)
        essid = (m.group(1).strip() if m and m.group(1).strip() and "\x00" not in m.group(1)
                 else "<wildcard>")

        with self._lock:
            if mac in self._probes:
                self._probes[mac].update(rssi, essid, card_ch)
            else:
                self._probes[mac] = Probe(mac, essid, card_ch, rssi)

    def _handle_client(self, lines, text, rssi, card_ch):
        bssid_m  = _BSSID.search(text)
        ap_bssid = bssid_m.group(1).upper() if bssid_m else None
        if not ap_bssid or ap_bssid == "FF:FF:FF:FF:FF:FF":
            return

        mac = None
        for m in _SA.finditer(text):
            c = m.group(1).upper()
            if c != ap_bssid and c != "FF:FF:FF:FF:FF:FF":
                mac = c
                break
        if not mac:
            return

        with self._lock:
            if mac in self._nets:   # skip known APs
                return
            net   = self._nets.get(ap_bssid)
            essid = net.essid   if net else "<unknown>"
            ch    = net.channel if net else card_ch
            if mac in self._clients:
                self._clients[mac].update(rssi, essid)
            else:
                self._clients[mac] = Client(mac, ap_bssid, essid, ch, rssi)

    def _dispatch_block(self, lines, card_ch):
        if not lines:
            return
        rssi = _parse_rssi(lines)
        if rssi is None:
            return
        text = "\n".join(lines)
        bl   = text.lower()
        if "probe request" in bl:
            self._handle_probe(lines, text, rssi, card_ch)
        elif "beacon" in bl:
            self._handle_beacon(lines, text, rssi, card_ch)
        else:
            self._handle_client(lines, text, rssi, card_ch)

    # ── Channel capture loop ──────────────────────────────────────────────────

    def _capture_channel(self, ch):
        set_channel(self.iface, ch)
        self.current_channel = ch

        # Capture: beacons | probe requests | ToDS data frames (client→AP)
        bpf = ("(wlan[0] == 0x80) or (wlan[0] == 0x40) or "
               "(type data and wlan[1] & 0x02 == 0x00 and wlan[1] & 0x01 == 0x01)")
        cmd = ["tcpdump", "-i", self.iface, "-v", "-e", "-l", "-xx",
               "--immediate-mode", bpf]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    text=True, bufsize=1)
        except FileNotFoundError:
            return

        q      = queue.Queue()
        reader = threading.Thread(target=_reader_thread, args=(proc, q), daemon=True)
        reader.start()

        deadline    = time.monotonic() + DWELL_S
        block_lines = []

        while time.monotonic() < deadline:
            timeout = max(0.005, deadline - time.monotonic())
            try:
                line = q.get(timeout=timeout)
            except queue.Empty:
                continue
            if line is None:
                break
            stripped = line.rstrip()
            if (_TIMESTAMP.match(stripped) or stripped == "") and block_lines:
                self._dispatch_block(block_lines, ch)
                block_lines = []
            if stripped:
                block_lines.append(stripped)

        if block_lines:
            self._dispatch_block(block_lines, ch)

        proc.terminate()
        try:
            proc.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            proc.kill()

    def run(self):
        while not self._stop_evt.is_set():
            for ch in CHANNELS:
                if self._stop_evt.is_set():
                    return
                while self.paused and not self._stop_evt.is_set():
                    time.sleep(0.1)
                self._capture_channel(ch)

    def stop(self):
        self._stop_evt.set()

    def restart(self):
        """Spawn a new worker thread, preserving all captured data."""
        self._stop_evt.clear()
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        return t

    def clear(self):
        with self._lock:
            self._nets.clear()
            self._clients.clear()
            self._probes.clear()

    def networks(self):
        with self._lock:
            nets = list(self._nets.values())
        nets.sort(key=lambda n: n.rssi, reverse=True)
        return nets

    def clients(self):
        with self._lock:
            cs = list(self._clients.values())
        cs.sort(key=lambda c: c.rssi, reverse=True)
        return cs

    def probes(self):
        with self._lock:
            ps = list(self._probes.values())
        ps.sort(key=lambda p: p.rssi, reverse=True)
        return ps

# ── Signal poller (used in graph view) ───────────────────────────────────────

class Poller(threading.Thread):
    """
    Locks onto one target (AP, client, or probe source) and captures RSSI
    samples, bucketing them into time-averaged plot points.
    """

    def __init__(self, iface, bssid, channel, essid=None,
                 probe_mode=False, client_mode=False):
        super().__init__(daemon=True)
        self.iface       = iface
        self.bssid       = bssid.upper()
        self.channel     = channel
        self.essid       = essid
        self.probe_mode  = probe_mode
        self.client_mode = client_mode
        self.paused      = False
        self._lock       = threading.Lock()
        self._samples    = deque()
        self._last       = None
        self._raw_bucket = []
        self._bucket_end = time.monotonic() + SAMPLE_INTERVAL
        self._total      = 0
        self._proc       = None

    def run(self):
        set_channel(self.iface, self.channel)

        if self.probe_mode:
            bpf = f"wlan[0] == 0x40 and ether src {self.bssid}"
        elif self.client_mode:
            bpf = (f"type data and wlan[1] & 0x01 == 0x01 "
                   f"and ether src {self.bssid}")
        else:
            bpf = f"wlan[0] == 0x80 and wlan addr3 {self.bssid}"

        cmd = ["tcpdump", "-i", self.iface, "-v", "-e", "-l",
               "--immediate-mode", bpf]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL,
                                          text=True, bufsize=1)
        except FileNotFoundError:
            return

        essid_pat = (_PROBE_SSID if self.probe_mode else _ESSID)

        for line in self._proc.stdout:
            if self.paused:
                continue

            # Update ESSID if we haven't resolved it yet
            if not self.essid or self.essid in ("<wildcard>", "<unknown>"):
                m = essid_pat.search(line)
                if m:
                    c = m.group(1).strip()
                    if c and "\x00" not in c:
                        with self._lock:
                            self.essid = c

            rssi = None
            for pat in _RSSI:
                m = pat.search(line)
                if m:
                    rssi = float(m.group(1))
                    break

            if rssi is not None:
                now = time.monotonic()
                self._raw_bucket.append(rssi)
                if now >= self._bucket_end:
                    avg = sum(self._raw_bucket) / len(self._raw_bucket)
                    with self._lock:
                        self._last = avg
                        self._total += 1
                        self._samples.append((datetime.now().strftime("%H:%M:%S"), avg))
                    self._raw_bucket = []
                    self._bucket_end = now + SAMPLE_INTERVAL

    def stop(self):
        if self._proc:
            self._proc.terminate()

    def snapshot(self, max_cols):
        """Return (last_dbm, essid, [(ts, dbm), ...], total_count)."""
        with self._lock:
            while len(self._samples) > max_cols:
                self._samples.popleft()
            return self._last, self.essid, list(self._samples), self._total

    def clear(self):
        """Reset graph history."""
        with self._lock:
            self._samples.clear()
            self._last       = None
            self._total      = 0
            self._raw_bucket = []

# ── Curses helpers ────────────────────────────────────────────────────────────

def safe(win, y, x, s, attr):
    """addstr that silently ignores out-of-bounds writes."""
    try:
        win.addstr(y, x, s, attr)
    except curses.error:
        pass


def dbm_to_row(dbm, graph_top, graph_rows):
    frac = (Y_MAX - max(Y_MIN, min(Y_MAX, dbm))) / (Y_MAX - Y_MIN)
    return graph_top + int(frac * (graph_rows - 1))

# ── Graph screen ──────────────────────────────────────────────────────────────

def run_graph(stdscr, poller, BRIGHT, THRESH, probe_mode=False, client_mode=False):
    """
    Real-time signal strength graph for a single target.

    Keys: space=pause  r=reset  esc=back  q=quit
    Returns True  → go back to scanner
            False → quit
    """
    frame_time = 1.0 / RENDER_HZ
    X_ORIGIN   = Y_LABEL_W + 1
    rows, cols = stdscr.getmaxyx()
    pad        = curses.newpad(rows, cols)

    while True:
        t0  = time.monotonic()
        key = stdscr.getch()

        if key in (ord('q'), ord('Q')):
            return False
        elif key == 27:                        # Escape = back to scanner
            return True
        elif key == ord(' '):
            poller.paused = not poller.paused
        elif key in (ord('r'), ord('R')):
            poller.clear()

        new_rows, new_cols = stdscr.getmaxyx()
        if (new_rows, new_cols) != (rows, cols):
            rows, cols = new_rows, new_cols
            pad = curses.newpad(rows, cols)

        pad.erase()

        HEADER_H   = 3
        FOOTER_H   = 2
        graph_rows = rows - HEADER_H - FOOTER_H
        graph_cols = cols - X_ORIGIN

        if graph_rows < 4 or graph_cols < 10:
            safe(pad, 0, 0, "Terminal too small — resize to continue", BRIGHT)
            pad.noutrefresh(0, 0, 0, 0, rows - 1, cols - 1)
            curses.doupdate()
            time.sleep(frame_time)
            continue

        graph_top  = HEADER_H
        graph_bot  = graph_top + graph_rows - 1
        thresh_row = (dbm_to_row(FUNCTIONAL_DBM, graph_top, graph_rows)
                      if Y_MIN <= FUNCTIONAL_DBM <= Y_MAX else None)

        last_sig, essid, sample_list, total = poller.snapshot(graph_cols)
        n = len(sample_list)

        # Header
        pause_tag  = "  ⏸ PAUSED" if poller.paused else ""
        essid_disp = essid if essid else "<listening…>"
        left  = (f" {poller.iface}  CH: {poller.channel}"
                 f"  {essid_disp}  {poller.bssid}{pause_tag}")
        right = "space: pause   r: reset   esc: back   q: quit"
        safe(pad, 1, 0,                         left[:cols - 1],  BRIGHT)
        safe(pad, 1, max(0, cols - len(right) - 1), right[:cols - 1], BRIGHT)

        if last_sig is not None:
            banner = f"{last_sig:+.0f} dBm"
            safe(pad, 2, (cols - len(banner)) // 2, banner[:cols - 1], THRESH)
        else:
            if probe_mode:
                msg = f" Listening for probe requests from {poller.bssid} on ch {poller.channel}… "
            elif client_mode:
                msg = f" Listening for data frames from {poller.bssid} on ch {poller.channel}… "
            else:
                msg = f" Listening for beacons from {poller.bssid} on ch {poller.channel}… "
            safe(pad, 2, (cols - len(msg)) // 2, msg[:cols - 1], BRIGHT)

        # Y-axis and grid
        for r in range(graph_top, graph_bot + 1):
            frac         = (r - graph_top) / max(graph_rows - 1, 1)
            dbm_val      = Y_MAX - frac * (Y_MAX - Y_MIN)
            nearest_tick = round(dbm_val / 5) * 5
            row_of_tick  = dbm_to_row(nearest_tick, graph_top, graph_rows)
            is_tick      = (r == row_of_tick and Y_MIN <= nearest_tick <= Y_MAX)

            if r == thresh_row:
                safe(pad, r, 0, f"{FUNCTIONAL_DBM:+4d}", THRESH)
                safe(pad, r, 4, " ", THRESH)
                for c in range(graph_cols):
                    safe(pad, r, X_ORIGIN + c, "╌" if c % 2 == 0 else " ", THRESH)
            elif is_tick:
                safe(pad, r, 0, f"{nearest_tick:+4d}", BRIGHT)
                safe(pad, r, 4, " ", BRIGHT)
                for c in range(graph_cols):
                    safe(pad, r, X_ORIGIN + c, "·", BRIGHT)
            else:
                safe(pad, r, 0, " " * Y_LABEL_W, BRIGHT)
            safe(pad, r, X_ORIGIN - 1, "│", BRIGHT)

        x_axis_row = graph_bot + 1
        safe(pad, x_axis_row, X_ORIGIN - 1, "└", BRIGHT)
        for c in range(graph_cols):
            safe(pad, x_axis_row, X_ORIGIN + c, "─", BRIGHT)

        # Plot
        prev_row = None
        for i, (ts, dbm) in enumerate(sample_list):
            col = X_ORIGIN + (graph_cols - n + i)
            row = dbm_to_row(dbm, graph_top, graph_rows)
            if prev_row is not None:
                for r in range(min(prev_row, row), max(prev_row, row) + 1):
                    if graph_top <= r <= graph_bot:
                        safe(pad, r, col, "│", BRIGHT)
            if graph_top <= row <= graph_bot:
                safe(pad, row, col, "●", BRIGHT)
            prev_row = row

        # Stats footer
        stats_row = x_axis_row + 1
        if stats_row < rows and n > 1:
            vals = [s[1] for s in sample_list]
            mn, mx, av = min(vals), max(vals), sum(vals) / len(vals)
            stats = (f"  Min: {mn:+.0f} dBm   Avg: {av:+.1f} dBm"
                     f"   Max: {mx:+.0f} dBm   Samples: {total}")
            safe(pad, stats_row, 0, stats[:cols - 1], BRIGHT)

        pad.noutrefresh(0, 0, 0, 0, rows - 1, cols - 1)
        curses.doupdate()
        time.sleep(max(0.0, frame_time - (time.monotonic() - t0)))

# ── Scanner screen ────────────────────────────────────────────────────────────

# Pane definitions: (index, title, empty message)
_PANE_DEFS = [
    (0, "---- Access Points ----",     "No beacons yet…"),
    (1, "---- Connected Clients ----", "No clients yet…"),
    (2, "---- Probes ----",            "No probes yet…"),
]

# Column widths (fixed)
_W_MAC  = 17
_W_PWR  = 4
_W_PKTS = 6
_W_CH   = 4
_W_ENC  = 9   # fits "WPA2-PSK", "WPA2-EAP", "WPA3-SAE", "WPA2/3"


def _format_row(p, obj, pane_w):
    """Format a single data row for pane p."""
    if p == 0:   # Access Points
        W_E  = max(4, pane_w - _W_MAC - _W_PWR - _W_PKTS - _W_CH - _W_ENC - 5)
        return (f" {obj.bssid:<{_W_MAC}}"
                f" {int(obj.rssi):>{_W_PWR}}"
                f" {obj.beacons:>{_W_PKTS}}"
                f" {obj.channel:>{_W_CH}}"
                f" {obj.enc:<{_W_ENC}}"
                f" {(obj.essid or '<hidden>')[:W_E]:<{W_E}}")
    elif p == 1: # Connected Clients
        W_E  = max(4, pane_w - _W_MAC - _W_PWR - _W_PKTS - _W_CH - 4)
        return (f" {obj.mac:<{_W_MAC}}"
                f" {int(obj.rssi):>{_W_PWR}}"
                f" {obj.count:>{_W_PKTS}}"
                f" {obj.channel:>{_W_CH}}"
                f" {(obj.essid or '<unknown>')[:W_E]:<{W_E}}")
    else:        # Probes
        W_E  = max(4, pane_w - _W_MAC - _W_PWR - _W_PKTS - _W_CH - 4)
        return (f" {obj.mac:<{_W_MAC}}"
                f" {int(obj.rssi):>{_W_PWR}}"
                f" {obj.count:>{_W_PKTS}}"
                f" {obj.channel:>{_W_CH}}"
                f" {(obj.essid or '<wildcard>')[:W_E]:<{W_E}}")


def _col_header(p, pane_w):
    """Column header string for pane p."""
    if p == 0:
        W_E = max(4, pane_w - _W_MAC - _W_PWR - _W_PKTS - _W_CH - _W_ENC - 5)
        return (f" {'BSSID':<{_W_MAC}} {'PWR':>{_W_PWR}} {'PKTS':>{_W_PKTS}}"
                f" {'CH':>{_W_CH}} {'ENC':<{_W_ENC}} {'ESSID':<{W_E}}")
    elif p == 1:
        W_E = max(4, pane_w - _W_MAC - _W_PWR - _W_PKTS - _W_CH - 4)
        return (f" {'MAC':<{_W_MAC}} {'PWR':>{_W_PWR}} {'PKTS':>{_W_PKTS}}"
                f" {'CH':>{_W_CH}} {'ESSID':<{W_E}}")
    else:
        W_E = max(4, pane_w - _W_MAC - _W_PWR - _W_PKTS - _W_CH - 4)
        return (f" {'MAC':<{_W_MAC}} {'PWR':>{_W_PWR}} {'PKTS':>{_W_PKTS}}"
                f" {'CH':>{_W_CH}} {'SSID':<{W_E}}")


def run_scanner(stdscr, scanner, BRIGHT, SEL, THRESH, panes):
    """
    Three-column scanner screen.

    panes  — list of pane indices to show (subset of [0, 1, 2])
    Keys:  h/l or ←/→ = switch pane   j/k or ↑/↓ = scroll
           Enter = select   space = pause   r = clear   q = quit
    Returns (kind, obj)  or  None to quit.
    """
    frame_time = 1.0 / RENDER_HZ
    n_panes    = len(panes)

    cursors    = {p: 0 for p in panes}
    scrolls    = {p: 0 for p in panes}
    active_idx = 0    # index into panes list

    while True:
        t0  = time.monotonic()
        key = stdscr.getch()

        nets    = scanner.networks()
        clients = scanner.clients()
        client_macs = {c.mac for c in clients}
        probes  = [p for p in scanner.probes() if p.mac not in client_macs]

        # Map pane index -> data list
        data = {0: nets, 1: clients, 2: probes}

        active_pane = panes[active_idx]
        lst         = data[active_pane]

        # Key handling
        if key in (ord('q'), ord('Q')):
            return None
        elif key in (curses.KEY_RIGHT, ord('l')):
            active_idx = (active_idx + 1) % n_panes
        elif key in (curses.KEY_LEFT, ord('h')):
            active_idx = (active_idx - 1) % n_panes
        elif key in (curses.KEY_UP, ord('k')):
            cursors[active_pane] = max(0, cursors[active_pane] - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            cursors[active_pane] = min(max(0, len(lst) - 1),
                                       cursors[active_pane] + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            if lst:
                idx = min(cursors[active_pane], len(lst) - 1)
                obj = lst[idx]
                kinds = {0: 'net', 1: 'client', 2: 'probe'}
                return (kinds[active_pane], obj)
        elif key in (ord('r'), ord('R')):
            scanner.clear()
            cursors = {p: 0 for p in panes}
            scrolls = {p: 0 for p in panes}
        elif key == ord(' '):
            scanner.paused = not scanner.paused

        rows, cols = stdscr.getmaxyx()
        stdscr.erase()

        # Row layout
        HEADER_ROW     = 0
        PANE_TITLE_ROW = 1
        COL_HDR_ROW    = 2
        LIST_TOP       = 3
        list_rows      = rows - LIST_TOP

        # Column layout: panes share width equally, separated by │
        n_dividers = n_panes - 1
        pane_w     = max(20, (cols - n_dividers) // n_panes)
        pane_xs    = [i * (pane_w + 1) for i in range(n_panes)]

        # Header
        pause_tag = "  ⏸ PAUSED" if scanner.paused else ""
        ch_str    = (f"CH {scanner.current_channel:>3}"
                     if scanner.current_channel else "CH  …")
        stats     = (f"[{ch_str}]   {len(nets)} APs"
                     f"   {len(clients)} clients"
                     f"   {len(probes)} probes"
                     f"{pause_tag}")
        keyhints  = "h/l: pane   j/k: scroll   enter: select   space: pause   r: reset   q: quit"
        safe(stdscr, HEADER_ROW, 0, stats, BRIGHT)
        safe(stdscr, HEADER_ROW, max(0, cols - len(keyhints) - 1), keyhints[:cols - 1], BRIGHT)

        # Vertical dividers
        for r in range(HEADER_ROW, rows):
            for i in range(1, n_panes):
                x = pane_xs[i] - 1
                if x < cols:
                    safe(stdscr, r, x, "│", BRIGHT)

        # Render panes
        for pi, p in enumerate(panes):
            px     = pane_xs[pi]
            lst    = data[p]
            is_act = (pi == active_idx)
            attr   = THRESH if is_act else BRIGHT

            # Clamp cursor and update scroll
            n_items = len(lst)
            cursors[p] = min(cursors[p], max(0, n_items - 1))
            cur = cursors[p]
            if cur < scrolls[p]:
                scrolls[p] = cur
            elif cur >= scrolls[p] + list_rows:
                scrolls[p] = cur - list_rows + 1

            # Pane title (centred)
            title = f" {_PANE_DEFS[p][1]} "
            tx    = px + max(0, (pane_w - len(title)) // 2)
            safe(stdscr, PANE_TITLE_ROW, tx, title[:pane_w - 1], attr)

            # Column header
            safe(stdscr, COL_HDR_ROW, px, _col_header(p, pane_w)[:pane_w], attr)

            # Data rows
            for i, obj in enumerate(lst[scrolls[p]: scrolls[p] + list_rows]):
                r       = LIST_TOP + i
                abs_idx = scrolls[p] + i
                row_attr = SEL if (abs_idx == cur and is_act) else BRIGHT
                safe(stdscr, r, px, _format_row(p, obj, pane_w)[:pane_w - 1], row_attr)

            if not lst:
                safe(stdscr, LIST_TOP, px + 1, _PANE_DEFS[p][2], BRIGHT)

            # Scroll indicators
            if scrolls[p] > 0:
                safe(stdscr, PANE_TITLE_ROW, px + pane_w - 2, "↑", BRIGHT)
            if scrolls[p] + list_rows < n_items:
                safe(stdscr, rows - 1, px + pane_w - 2, "↓", BRIGHT)

        stdscr.refresh()
        time.sleep(max(0.0, frame_time - (time.monotonic() - t0)))

# ── App orchestration ─────────────────────────────────────────────────────────

def run_app(stdscr, iface, panes):
    """Main curses application: scanner → graph → scanner loop."""
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_MAGENTA, -1)
    curses.init_pair(2, curses.COLOR_YELLOW,  -1)
    curses.init_pair(3, curses.COLOR_BLACK,   curses.COLOR_MAGENTA)

    BRIGHT = curses.color_pair(1) | curses.A_BOLD
    THRESH = curses.color_pair(2) | curses.A_BOLD
    SEL    = curses.color_pair(3) | curses.A_BOLD

    scanner = Scanner(iface)
    scanner.start()

    try:
        while True:
            result = run_scanner(stdscr, scanner, BRIGHT, SEL, THRESH, panes)
            if result is None:
                break

            # Stop channel-hopping while the Poller locks the card to one channel,
            # but keep the scanner object (and all its captured data) alive.
            scanner.stop()
            scanner.join(timeout=2)

            kind, obj = result
            if kind == 'net':
                poller = Poller(iface, obj.bssid, obj.channel, obj.essid)
            elif kind == 'probe':
                poller = Poller(iface, obj.mac, obj.channel, obj.essid,
                                probe_mode=True)
            else:   # client
                poller = Poller(iface, obj.mac, obj.channel,
                                f"{obj.essid} ({obj.ap_bssid})",
                                client_mode=True)

            poller.start()
            go_back = run_graph(stdscr, poller, BRIGHT, THRESH,
                                probe_mode=(kind == 'probe'),
                                client_mode=(kind == 'client'))
            poller.stop()
            poller.join(timeout=2)

            if not go_back:
                break

            # Resume scanning — reuse the existing scanner so all previously
            # discovered networks, clients and probes are still visible immediately.
            scanner.restart()

    finally:
        try:
            scanner.stop()
        except Exception:
            pass

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="airohunt-ng",
        description="WiFi signal strength monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo airohunt-ng wlan0
  sudo airohunt-ng wlan0 --band 5 -AC
  sudo airohunt-ng wlan0 -c 6 --bssid BC:0F:9A:17:9E:EC
        """,
    )
    parser.add_argument("interface",
                        help="Monitor-mode interface (e.g. wlan0)")
    parser.add_argument("--band", choices=["2.4", "5", "both"], default="2.4",
                        help="Band to scan: 2.4 GHz (default), 5 GHz, or both")
    parser.add_argument("-c", "--channel", type=int, metavar="CH",
                        help="Lock to a single channel instead of hopping")
    parser.add_argument("--bssid", metavar="MAC",
                        help="Go straight to the signal graph for this BSSID "
                             "(requires -c)")
    parser.add_argument("-A", dest="show_aps",     action="store_true",
                        help="Show Access Points pane")
    parser.add_argument("-C", dest="show_clients", action="store_true",
                        help="Show Connected Clients pane")
    parser.add_argument("-P", dest="show_probes",  action="store_true",
                        help="Show Probes pane")

    # ── Validation ────────────────────────────────────────────────────────────
    if os.geteuid() != 0:
        print("This script must be run as root.\n")
        parser.print_help()
        exit(1)

    args = parser.parse_args()

    if not check_monitor_mode(args.interface):
        parser.error(f"{args.interface} is not in monitor mode.")

    if not shutil.which("tcpdump"):
        parser.error("tcpdump not found — install with: apt install tcpdump")

    if args.bssid and not args.channel:
        parser.error("--bssid requires -c <channel>")

    if args.bssid and not re.fullmatch(
            r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", args.bssid):
        parser.error(f"invalid MAC address: {args.bssid!r}")

    # ── Channel list ──────────────────────────────────────────────────────────
    global CHANNELS
    if args.channel:
        CHANNELS = [args.channel]
    else:
        CHANNELS = get_channels(args.interface, band=args.band)
    # else: 2.4 GHz default already set

    # ── Pane selection ────────────────────────────────────────────────────────
    # If no -A/-C/-P flags given, show all three.
    if args.show_aps or args.show_clients or args.show_probes:
        panes = ([0] if args.show_aps     else []) + \
                ([1] if args.show_clients else []) + \
                ([2] if args.show_probes  else [])
    else:
        panes = [0, 1, 2]

    # ── Launch ────────────────────────────────────────────────────────────────
    try:
        if args.bssid:
            # Direct graph mode — bypass the scanner entirely
            def _direct(stdscr, iface, bssid, channel):
                curses.curs_set(0); stdscr.nodelay(True)
                curses.start_color(); curses.use_default_colors()
                curses.init_pair(1, curses.COLOR_MAGENTA, -1)
                curses.init_pair(2, curses.COLOR_YELLOW,  -1)
                BRIGHT = curses.color_pair(1) | curses.A_BOLD
                THRESH = curses.color_pair(2) | curses.A_BOLD
                poller = Poller(iface, bssid, channel)
                poller.start()
                try:
                    run_graph(stdscr, poller, BRIGHT, THRESH)
                finally:
                    poller.stop()
                    poller.join(timeout=2)

            curses.wrapper(_direct, args.interface, args.bssid, args.channel)
        else:
            curses.wrapper(run_app, args.interface, panes)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
