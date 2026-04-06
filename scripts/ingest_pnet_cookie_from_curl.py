#!/usr/bin/env python3
"""Read curl text from stdin or file; extract -b $'...' cookie; merge HR_PORTAL_COOKIE into repo .env."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"


def extract_cookie(text: str) -> str:
    i = text.find("-b $'")
    if i < 0:
        print("ERROR: -b $' not found in curl", file=sys.stderr)
        sys.exit(1)
    i += len("-b $'")
    j = text.find("' \\", i)
    if j < 0:
        j = text.find("' \\\n", i)
    if j < 0:
        print("ERROR: closing ' \\\\ not found", file=sys.stderr)
        sys.exit(1)
    s = text[i:j]

    s = s.replace("\\'", "'")
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return s


def merge_env(cookie: str) -> None:
    esc = cookie.replace("\\", "\\\\").replace('"', '\\"')
    cookie_line = f'HR_PORTAL_COOKIE="{esc}"\n'
    raw = ENV_PATH.read_text(encoding="utf-8-sig") if ENV_PATH.exists() else ""
    out = []
    replaced = False
    for line in raw.splitlines(keepends=True):
        if line.startswith("HR_PORTAL_COOKIE="):
            if not replaced:
                out.append(cookie_line)
                replaced = True
            continue
        out.append(line)
    if not replaced:
        if out and not (out[-1].endswith("\n")):
            out[-1] += "\n"
        out.append(cookie_line)
    ENV_PATH.write_text("".join(out), encoding="utf-8")


def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ("-", "/dev/stdin"):
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()
    cookie = extract_cookie(text)
    merge_env(cookie)
    print(f"OK: wrote HR_PORTAL_COOKIE to .env ({len(cookie)} chars)")


if __name__ == "__main__":
    main()
