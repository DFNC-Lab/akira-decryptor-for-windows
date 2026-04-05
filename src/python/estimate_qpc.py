# SPDX-FileCopyrightText: 2026 Donghwoo Cho
# SPDX-License-Identifier: Apache-2.0

"""
estimate_qpc.py -- Back-calculate QPC (QueryPerformanceCounter) value at the time of Akira infection.

Usage:
  python estimate_qpc.py                          (when Akira log is in the same folder)
  python estimate_qpc.py --log "C:\\path\\Log-*.txt"
  python estimate_qpc.py --tz +09:00              (manually specify timezone)
  python estimate_qpc.py --no-reboot              (direct back-calculation without reboot)

Principle:
  1) Capture (QPC_now, time_now) pair from the current session
  2) Query boot event (EventID 12) of the current session
  3) bios_offset = QPC_uptime - wallclock_uptime  (time from BIOS POST to kernel entry)
  4) Find the boot event of the infection session:
     QPC_infection = QPF * ((T_infection - T_session_boot) + bios_offset)
"""

import re, sys, os, io, argparse
from pathlib import Path
import ctypes, subprocess, xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

# Force UTF-8 stdout/stderr on Windows (prevents cp949 encoding errors)
if sys.platform == 'win32':
    subprocess.run('chcp 65001', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ═══════════════════════════════════════════════════════════════════════════
# Banner / UI helpers
# ═══════════════════════════════════════════════════════════════════════════
BOX_W = 54

def _hline():
    return '+' + '=' * BOX_W + '+'

def _sep():
    return '+' + '-' * BOX_W + '+'

def _row(text):
    return '|  ' + f'{text:{BOX_W - 4}s}' + '  |'

def print_banner():
    print(_hline())
    print(_row("Step 1. QPC Estimator"))
    print(_row("Estimate reference QPC value from Akira log"))
    print(_hline())
    print()

def print_result_box(ref_time, ref_qpc, qpf):
    print(_hline())
    print(_row("Result"))
    print(_sep())
    print(_row(f'ref_time:  "{ref_time}"'))
    print(_row(f'ref_qpc:   {ref_qpc}'))
    print(_row(f'qpf:       {qpf}'))
    print(_hline())

def pause_exit(code=1):
    """Wait before exiting so the window does not close immediately in EXE builds."""
    try:
        input("\nPress Enter to exit.")
    except EOFError:
        pass
    sys.exit(code)

# ═══════════════════════════════════════════════════════════════════════════
# Windows API
# ═══════════════════════════════════════════════════════════════════════════
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

def get_qpf():
    x = ctypes.c_longlong()
    kernel32.QueryPerformanceFrequency(ctypes.byref(x))
    return x.value

def get_qpc():
    x = ctypes.c_longlong()
    kernel32.QueryPerformanceCounter(ctypes.byref(x))
    return x.value

# ═══════════════════════════════════════════════════════════════════════════
# Timezone / time utilities
# ═══════════════════════════════════════════════════════════════════════════
def get_local_tz():
    """Return the system local timezone UTC offset as a timezone object."""
    now = datetime.now()
    utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
    offset = now - utc_now
    # Round to remove sub-second error
    total_sec = round(offset.total_seconds())
    return timezone(timedelta(seconds=total_sec))

def iso_utc(s):
    """Convert an ISO 8601 string to a UTC datetime."""
    s = s[:-1] + '+00:00' if s.endswith('Z') else s
    s = re.sub(r'(\.\d+)([+-].+)?$',
               lambda m: '.' + (m.group(1)[1:] + '000000')[:6] + (m.group(2) or ''), s)
    return datetime.fromisoformat(s).astimezone(timezone.utc)

# ═══════════════════════════════════════════════════════════════════════════
# Windows Event Log query
# ═══════════════════════════════════════════════════════════════════════════
def boot_times(n=100):
    """Return a list of boot times (UTC, ascending) from EventID 12 (Kernel-General) records."""
    q = "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12)]]"
    try:
        out = subprocess.run(
            ["wevtutil", "qe", "System", "/q:" + q, "/c:" + str(n), "/rd:true", "/f:xml"],
            capture_output=True, text=True, check=True, timeout=30
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  [!] wevtutil execution failed: {e}", file=sys.stderr)
        return []

    if not out:
        return []

    root = ET.fromstring("<Events>" + out + "</Events>")
    ts = [iso_utc(x.attrib["SystemTime"])
          for x in root.iter()
          if x.tag.endswith("TimeCreated") and "SystemTime" in x.attrib]
    ts.sort()
    return ts

def find_session(boots, ts):
    """Return the boot time of the session that contains timestamp ts."""
    if not boots or ts < boots[0]:
        return None
    for a, b in zip(boots, boots[1:]):
        if a <= ts < b:
            return a
    return boots[-1]

# ═══════════════════════════════════════════════════════════════════════════
# Akira log parsing
# ═══════════════════════════════════════════════════════════════════════════
LOG_FILENAME_REGEX = re.compile(r'^Log-\d{2}-\d{2}-\d{4}-\d{2}-\d{2}-\d{2}\.txt$')
LINE_TS_REGEX = re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]')

def find_akira_log(search_dir):
    """Return the most recent Akira log file in the specified directory."""
    logs = [p for p in Path(search_dir).iterdir()
            if p.is_file() and LOG_FILENAME_REGEX.match(p.name)]
    if not logs:
        return None
    return max(logs, key=lambda p: p.stat().st_mtime)

def parse_akira_log_timestamp(logpath, local_tz):
    """Extract the first valid timestamp from an Akira log (local_tz -> UTC)."""
    try:
        text = Path(logpath).read_text(encoding="mbcs", errors="ignore")
    except Exception:
        text = Path(logpath).read_text(encoding="utf-8", errors="ignore")

    for line in text.splitlines():
        line = line.strip()
        m = LINE_TS_REGEX.match(line)
        if m:
            ts_str = m.group(1)  # "YYYY-MM-DD HH:MM:SS.mmm"
            local_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=local_tz)
            return local_dt.astimezone(timezone.utc), ts_str

    return None, None

# ═══════════════════════════════════════════════════════════════════════════
# BIOS offset calibration
# ═══════════════════════════════════════════════════════════════════════════
def _measure_bios_offset_once(qpf, boot_time_utc):
    """Single BIOS offset measurement (QPC/wallclock capture)."""
    qpc_now = get_qpc()
    time_now = datetime.now(timezone.utc)
    qpc_uptime = qpc_now / qpf
    wall_uptime = (time_now - boot_time_utc).total_seconds()
    return qpc_uptime - wall_uptime, qpc_now, time_now


def estimate_bios_offset(qpf, current_boot_time_utc, n_samples=21):
    """
    Measure the BIOS-to-EventID12 offset in the current session.
    Takes n_samples repeated measurements and uses the median for reproducibility.

    The QPC counter starts at BIOS POST, but EventID 12 is recorded after kernel
    initialization. This difference (= BIOS offset) is measured in the current
    session and then applied to past sessions.

    Returns:
        bios_offset_sec (float): Difference in seconds between QPC=0 and EventID 12 (median)
        confidence (str): "high" | "medium" | "low"
        qpc_now (int): Representative QPC value (at median measurement point)
        time_now (datetime): Representative wallclock (at median measurement point)
    """
    import time as _time
    samples = []
    for _ in range(n_samples):
        offset, qpc_now, time_now = _measure_bios_offset_once(qpf, current_boot_time_utc)
        samples.append((offset, qpc_now, time_now))
        _time.sleep(0.005)  # 5ms interval

    # Select median (sort then pick middle)
    samples.sort(key=lambda x: x[0])
    median_idx = len(samples) // 2
    bios_offset_sec, qpc_now, time_now = samples[median_idx]

    # Confidence assessment
    if bios_offset_sec < 0:
        confidence = "low"    # NTP shifted time forward, or measurement error
    elif bios_offset_sec > 120:
        confidence = "low"    # Over 2 minutes is abnormal
    elif bios_offset_sec > 60:
        confidence = "medium"
    else:
        confidence = "high"

    return bios_offset_sec, confidence, qpc_now, time_now

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(
        description="Akira infection-time QPC back-calculator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python estimate_qpc.py                           # Auto-detect Akira log in current folder
  python estimate_qpc.py --log "C:\\Log-03-20-2026-12-34-56.txt"
  python estimate_qpc.py --tz +09:00               # Manually specify timezone
  python estimate_qpc.py --no-reboot               # Back-calculate without reboot (same session)
""")
    ap.add_argument("--log", help="Path to Akira log file (auto-detected in current folder if not specified)")
    ap.add_argument("--tz", help="Victim PC timezone (e.g., +09:00, -05:00). Uses system timezone if not specified")
    ap.add_argument("--no-reboot", action="store_true",
                    help="No reboot since infection (direct QPC back-calculation)")
    ap.add_argument("--debug", action="store_true", help="Print debug information")
    args = ap.parse_args()

    # ── Banner ──
    print()
    print_banner()

    # ── Timezone ──
    if args.tz:
        # "+09:00" → timedelta
        if not re.match(r'^[+-]\d{1,2}:\d{2}$', args.tz):
            print(f"  Error: Invalid timezone format: '{args.tz}'. Expected +HH:MM or -HH:MM.",
                  file=sys.stderr)
            pause_exit(1)
        sign = 1 if args.tz[0] == '+' else -1
        parts = args.tz.lstrip('+-').split(':')
        hours = int(parts[0])
        minutes = int(parts[1]) if len(parts) > 1 else 0
        local_tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))
    else:
        local_tz = get_local_tz()

    tz_name = f"UTC{'+' if local_tz.utcoffset(None).total_seconds() >= 0 else ''}" \
              f"{int(local_tz.utcoffset(None).total_seconds()) // 3600:02d}:" \
              f"{abs(int(local_tz.utcoffset(None).total_seconds()) % 3600) // 60:02d}"

    if args.debug:
        print(f"  [DBG] Timezone: {tz_name}")

    # ── Akira log file discovery ──
    if args.log:
        logpath = Path(args.log)
    else:
        script_dir = Path(sys.argv[0]).resolve().parent
        logpath = find_akira_log(script_dir)
        if not logpath:
            print("  Error: Akira log file (Log-*.txt) not found in current directory.", file=sys.stderr)
            print("         Use --log to specify the path manually.", file=sys.stderr)
            pause_exit(1)

    # ── Extract infection timestamp ──
    time_target_utc, ts_str = parse_akira_log_timestamp(logpath, local_tz)
    if not time_target_utc:
        print(f"  Error: No timestamp found in log: {logpath}", file=sys.stderr)
        pause_exit(1)

    # ── Capture QPF ──
    qpf = get_qpf()

    # ── Print infection info ──
    if args.no_reboot:
        method_str = "No reboot (direct back-calculation)"
    else:
        method_str = "EventLog + BIOS offset calibration"

    print(f"  Infection log:     {logpath.name}")
    print(f"  Infection time:    {ts_str} ({tz_name})")
    print(f"  Method:            {method_str}")
    print()

    if args.debug:
        print(f"  [DBG] Full log path: {logpath}")
        print(f"  [DBG] UTC conversion: {time_target_utc.isoformat()}")
        print(f"  [DBG] QPF: {qpf:,}")
        print()

    # ══════════════════════════════════════════════════════════════════════
    # Mode A: No reboot -- direct QPC back-calculation (most accurate)
    # ══════════════════════════════════════════════════════════════════════
    if args.no_reboot:
        # Get stable (QPC, wallclock) pair using median of 21 measurements
        import time as _time
        pairs = []
        for _ in range(21):
            q = get_qpc(); t = datetime.now(timezone.utc)
            pairs.append((q, t, q / qpf - (t - time_target_utc).total_seconds()))
            _time.sleep(0.005)
        pairs.sort(key=lambda x: x[2])
        qpc_now, time_now, _ = pairs[len(pairs) // 2]

        delta_sec = (time_now - time_target_utc).total_seconds()
        C_inf = int(round(qpc_now - qpf * delta_sec))

        if args.debug:
            print(f"  [DBG] QPC_now: {qpc_now} (median of 21)")
            print(f"  [DBG] time_now: {time_now.isoformat()}")
            print(f"  [DBG] Current-to-infection interval: {delta_sec:.3f}s")
            # Error estimate: NTP drift
            drift_ppm = 10
            drift_ticks = int(abs(delta_sec) * qpf * drift_ppm / 1e6)
            print(f"  [DBG] NTP drift (+/-{drift_ppm}ppm): +/-{drift_ticks} ticks = +/-{drift_ticks/qpf*1000:.1f}ms")
            print(f"  [DBG] Recommended --max-batch: {max(500_000_000, drift_ticks * 200)}")
            print()

        # Overflow / underflow guard
        if C_inf <= 0:
            print(f"  [!] Warning: Back-calculated QPC is negative ({C_inf}).", file=sys.stderr)
            print(f"      The system was likely rebooted after infection.", file=sys.stderr)
            print(f"      Re-run without --no-reboot.", file=sys.stderr)
            print(file=sys.stderr)
        elif C_inf > 2**63:
            print(f"  [!] Warning: Back-calculated QPC is abnormally large ({C_inf}).", file=sys.stderr)
            print(f"      Infection time may be in the future, or input may be incorrect.", file=sys.stderr)
            print(file=sys.stderr)
        elif delta_sec > 86400 * 30:
            print(f"  [!] Warning: {delta_sec/86400:.0f} days elapsed since infection.", file=sys.stderr)
            print(f"      Accuracy may be reduced due to accumulated NTP drift.", file=sys.stderr)
            print(f"      Consider increasing --max-batch.", file=sys.stderr)
            print(file=sys.stderr)

    # ══════════════════════════════════════════════════════════════════════
    # Mode B: After reboot -- EventLog + BIOS offset calibration
    # ══════════════════════════════════════════════════════════════════════
    else:
        boots = boot_times(100)
        if not boots:
            print("  Error: No boot records found in Windows Event Log.", file=sys.stderr)
            pause_exit(1)

        # Current session boot time
        current_boot = boots[-1]

        if args.debug:
            print(f"  [DBG] Detected {len(boots)} boot records")
            for i, b in enumerate(boots[-5:]):
                print(f"    [{len(boots)-5+i}] {b.astimezone(local_tz).isoformat()}")

        # BIOS offset measurement (current session, median of 21)
        bios_offset_sec, confidence, qpc_now, time_now = estimate_bios_offset(qpf, current_boot)

        if args.debug:
            print(f"\n  [DBG] BIOS offset measurement (current session, median of 21)")
            print(f"    QPC uptime:       {qpc_now/qpf:.3f}s")
            print(f"    Wallclock uptime: {(time_now - current_boot).total_seconds():.3f}s")
            print(f"    BIOS offset:      {bios_offset_sec:.6f}s (confidence: {confidence})")

        if confidence == "low":
            print(f"\n  [!] Warning: BIOS offset confidence is low.", file=sys.stderr)
            print(f"      NTP time adjustment may have occurred, or the current session is abnormal.", file=sys.stderr)
            print(f"      Consider using --no-reboot mode or Frida hook (analyze_qpc.py --anchor).", file=sys.stderr)

        # Find infection session
        T_session = find_session(boots, time_target_utc)
        if not T_session:
            print(f"  Error: Cannot find boot session containing infection time ({time_target_utc.isoformat()}).",
                  file=sys.stderr)
            print(f"    Oldest boot record: {boots[0].astimezone(local_tz).isoformat()}", file=sys.stderr)
            pause_exit(1)

        if args.debug:
            print(f"    Infection session boot: {T_session.astimezone(local_tz).isoformat()}")

        # QPC back-calculation: (infection_time - session_boot_time + BIOS_offset) * QPF
        wallclock_since_boot = (time_target_utc - T_session).total_seconds()
        qpc_since_boot = wallclock_since_boot + bios_offset_sec
        C_inf = int(round(qpf * qpc_since_boot))

        # Overflow / underflow guard
        if C_inf <= 0:
            print(f"\n  [!] Warning: Back-calculated QPC is negative ({C_inf}).", file=sys.stderr)
            print(f"      Infection time is before boot time, or BIOS offset measurement is abnormal.", file=sys.stderr)
            C_inf = max(C_inf, 1)
        elif C_inf > 2**63:
            print(f"\n  [!] Warning: Back-calculated QPC is abnormally large ({C_inf}).", file=sys.stderr)
            print(f"      Boot session identification may be incorrect.", file=sys.stderr)
        elif qpc_since_boot < 0:
            print(f"\n  [!] Warning: QPC uptime is negative ({qpc_since_boot:.3f}s).", file=sys.stderr)
            print(f"      Infection time was calculated as before boot.", file=sys.stderr)

        if args.debug:
            print(f"\n  [DBG] Wallclock (infection-boot): {wallclock_since_boot:.3f}s")
            print(f"  [DBG] + BIOS offset:             {bios_offset_sec:.3f}s")
            print(f"  [DBG] = Estimated QPC uptime:    {qpc_since_boot:.3f}s")

            # Error estimate
            bios_var_sec = 5.0
            ntp_adj_sec = 1.0
            total_error_sec = bios_var_sec + ntp_adj_sec
            total_error_ticks = int(total_error_sec * qpf)

            print(f"\n  [DBG] Error estimate:")
            print(f"    BIOS offset variation: +/-{bios_var_sec:.0f}s (between boots)")
            print(f"    NTP adjustment error:  +/-{ntp_adj_sec:.0f}s")
            print(f"    Total error:           +/-{total_error_sec:.0f}s = +/-{total_error_ticks:,} ticks")
            print(f"    Recommended --max-batch: {total_error_ticks * 200}")

            if confidence != "low":
                C_lo = int(round(qpf * (qpc_since_boot - total_error_sec)))
                C_hi = int(round(qpf * (qpc_since_boot + total_error_sec)))
                print(f"    ref_qpc range:     [{C_lo}, {C_hi}]")
            print()

    # ── Final result output ──
    print_result_box(ts_str, C_inf, qpf)
    print()
    print(f"  Next step:")
    print(f'  Step2_SeedScanner.exe <infected_path> "{ts_str}" {C_inf}')
    print()

    try:
        input("Press Enter to exit.")
    except EOFError:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}", file=sys.stderr)
        pause_exit(1)
