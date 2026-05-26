#!/usr/bin/env python3
"""Sanitized replay of `nexus_proxy_scan.py --include-compromised`.

Used only for demo recordings (vhs / asciinema) — does NOT contact Nexus
and does NOT read .env. All hostnames, repo names, and user IDs are
generic placeholders.
"""

from __future__ import annotations

import sys
import time

TOTAL = 13503
CONFIRMED = 13484
SUSPECTED = 19
WORKERS = 12
REPOS = [
    "npm-internal",
    "team-app-npm-3rdparty",
    "team-app-npm-release",
    "team-app-npm-snapshots",
    "proxy-npm",
]


def _render_progress(completed: int, total: int, rate: float,
                     hits: int, eta: float) -> None:
    bar_width = 24
    filled = int(bar_width * completed / total) if total else 0
    bar = "█" * filled + "░" * (bar_width - filled)
    pct = (100 * completed / total) if total else 0
    msg = (f"  [{bar}] {pct:5.1f}%  {completed}/{total}  "
           f"{rate:.0f}/s  hits={hits}  eta {eta:.0f}s")
    if sys.stdout.isatty():
        sys.stdout.write("\r\033[K" + msg)
        sys.stdout.flush()
    else:
        print(msg, flush=True)


def main() -> int:
    print("\U0001F4E6 Nexus: https://nexus.example.internal")
    print("\U0001F4CB SSOT:  public/data/malicious-packages.json")
    print(
        f"\U0001F3AF Targets: {TOTAL} ({CONFIRMED} confirmed + {SUSPECTED} suspected) "
        "[filter: malicious_intent + compromised_legitimate + suspected]"
    )
    print(
        f"\U0001F4DA npm repositories on instance: {len(REPOS) + 22} "
        f"({', '.join(REPOS)}...)"
    )
    print()
    print(f"\U0001F50D Scanning {TOTAL} targets with {WORKERS} workers...")

    # Replay progress with realistic timing, compressed into ~6s for the GIF.
    start = time.monotonic()
    step = 500
    total_runtime = 6.0
    ticks = TOTAL // step
    per_tick = total_runtime / ticks
    completed = 0
    rate = 155.0
    for _ in range(ticks):
        completed += step
        elapsed = time.monotonic() - start
        eta = max(0.0, (TOTAL - completed) / rate)
        _render_progress(completed, TOTAL, rate, 0, eta)
        time.sleep(per_tick)
    completed = TOTAL
    _render_progress(completed, TOTAL, rate, 0, 0.0)
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    print(f"  done in 87.1s ({TOTAL} targets, 0 errors, 0 hit rows)")
    print()
    print("\U0001F4C4 Result: internal/reports/data/nexus-proxy-scan-result.json")
    print(f"   Targets probed: {TOTAL} (one global-search call each)")
    print(f"   Hit rows: 0  (confirmed=0 suspected=0, a target may hit in >1 repo)")
    print(f"   Risk: {{'LOW': {TOTAL}}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
