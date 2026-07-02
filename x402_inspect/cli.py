"""x402-inspect CLI: decode + validate an x402 header/payload."""

from __future__ import annotations

import argparse
import json
import sys

from .core import Level, inspect

_COLOR = {Level.OK: "\033[32m", Level.WARN: "\033[33m", Level.ERROR: "\033[31m"}
_MARK = {Level.OK: "ok", Level.WARN: "warn", Level.ERROR: "FAIL"}
_RESET = "\033[0m"


def _fmt(level: Level, use_color: bool) -> str:
    tag = _MARK[level]
    return f"{_COLOR[level]}{tag}{_RESET}" if use_color else tag


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="x402-inspect",
        description="Decode and validate an x402 message (PAYMENT-REQUIRED / "
        "PAYMENT-SIGNATURE / PAYMENT-RESPONSE header value, base64 or raw JSON).",
    )
    p.add_argument("value", nargs="?", help="header value or JSON; omit to read stdin")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    args = p.parse_args(argv)

    value = args.value if args.value is not None else sys.stdin.read()
    rep = inspect(value)

    if args.json:
        print(
            json.dumps(
                {
                    "kind": rep.kind.value,
                    "encoding": rep.encoding,
                    "ok": rep.ok,
                    "findings": [
                        {"level": f.level.value, "path": f.path, "message": f.message}
                        for f in rep.findings
                    ],
                    "decoded": rep.obj,
                },
                indent=2,
            )
        )
        return 0 if rep.ok else 1

    use_color = sys.stdout.isatty() and not args.no_color
    print(f"kind:     {rep.kind.value}")
    print(f"encoding: {rep.encoding}")
    if not rep.findings:
        print("findings: none")
    else:
        print("findings:")
        for f in rep.findings:
            loc = f" {f.path}" if f.path else ""
            print(f"  [{_fmt(f.level, use_color)}]{loc}: {f.message}")
    print(f"result:   {'VALID' if rep.ok else 'INVALID'}")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
