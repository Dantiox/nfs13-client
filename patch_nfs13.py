#!/usr/bin/env python3
# Copyright (C) 2026 sn0wd0wn (gregel, Dantiox, Alexes)
# SPDX-License-Identifier: AGPL-3.0-only
"""Interoperability adapter script for NFS13 executable.

Applies configuration offsets enabling local loopback and standalone profile
mode for private LAN/VPN gameplay in accordance with 17 U.S.C. § 1201(f)
(interoperability exception) and Directive 2009/24/EC Article 6.
Does not contain or distribute any proprietary game code or assets.

The patch is a list of byte replacements. It only applies to the exact
executable it was made from (checked by SHA-256), writes a new file next to
the original and never modifies NFS13.exe itself.

    python patch_nfs13.py "C:\\Games\\Need for Speed Most Wanted\\NFS13.exe"
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

PATCH_FILE = Path(__file__).with_name("patches") / "nfs13_online.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("exe", type=Path, help="path to the original NFS13.exe")
    parser.add_argument("--out", type=Path,
                        help="output file (default: NFS13.online.exe next to the input)")
    parser.add_argument("--patch", type=Path, default=PATCH_FILE,
                        help="patch description (default: %(default)s)")
    args = parser.parse_args()

    patch = json.loads(args.patch.read_text(encoding="utf-8"))
    data = bytearray(args.exe.read_bytes())

    digest = hashlib.sha256(data).hexdigest()
    if digest == patch["patched_sha256"]:
        print("This file is already patched.")
        return 0
    if len(data) != patch["size"] or digest != patch["base_sha256"]:
        print(f"Unsupported executable: size={len(data)} sha256={digest}", file=sys.stderr)
        print(f"Expected sha256={patch['base_sha256']}", file=sys.stderr)
        return 1

    for item in patch["patches"]:
        offset = int(item["offset"], 16)
        original = bytes.fromhex(item["original"])
        patched = bytes.fromhex(item["patched"])
        if data[offset:offset + len(original)] != original:
            print(f"Unexpected bytes at {item['offset']}", file=sys.stderr)
            return 1
        data[offset:offset + len(patched)] = patched

    result = hashlib.sha256(data).hexdigest()
    if result != patch["patched_sha256"]:
        print(f"Patched file has an unexpected sha256={result}", file=sys.stderr)
        return 1

    out = args.out or args.exe.with_name("NFS13.online.exe")
    out.write_bytes(data)
    print(f"Wrote {out}")
    print("Start the game with this file instead of NFS13.exe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
