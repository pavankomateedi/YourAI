#!/usr/bin/env python3
"""Generate production key material.

  python scripts/gen_keys.py kek                 # print a base64 32-byte KEK
  python scripts/gen_keys.py master OUT [--kek B64]  # write a master key file,
                                                     # wrapped under the KEK if given

Never commit the output. Store the KEK in your secret manager and the master key
file as a mounted secret (KMS-wrapped in production).
"""

from __future__ import annotations

import base64
import os
import sys


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in {"kek", "master"}:
        print(__doc__)
        return 2

    if argv[0] == "kek":
        print(base64.b64encode(os.urandom(32)).decode())
        return 0

    # master key
    if len(argv) < 2:
        print("usage: gen_keys.py master OUT [--kek B64]")
        return 2
    out_path = argv[1]
    kek_b64 = None
    if "--kek" in argv:
        kek_b64 = argv[argv.index("--kek") + 1]

    master = os.urandom(32)
    if kek_b64:
        from secure_context_pipeline.security.keys import LocalEnvelopeWrapping

        on_disk = LocalEnvelopeWrapping(kek=base64.b64decode(kek_b64)).wrap(master)
        note = "wrapped under provided KEK"
    else:
        on_disk = master
        note = "PLAINTEXT (provide --kek to wrap; required for production)"

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(on_disk)
    print(f"Wrote master key to {out_path} ({note}).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
