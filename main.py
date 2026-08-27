"""Secret Scanner entry point.

PHASE 2: discover files in a directory. Secret detection is not implemented
yet. A full argparse CLI arrives in a later phase.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scanner import Scanner


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("Secret Scanner")
        print("Usage: python main.py <path>")
        print("PHASE 2 discovers files only. Secret detection comes later.")
        return 2

    target = Path(args[0])
    scanner = Scanner()

    try:
        files = scanner.discover_files(target)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 2

    print("Secret Scanner")
    print(f"Target: {target}")
    print(f"Files discovered: {len(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
