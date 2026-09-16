"""Implement independent vulnerable, patched and benign effect checks."""

import sys
import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    parser.parse_args()
    # Independently inspect effect evidence and write verdict.json; do not rerun PoC.
    print("NOT IMPLEMENTED: evidence verification for GHSA-g53w-w6mj-hrpp", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
