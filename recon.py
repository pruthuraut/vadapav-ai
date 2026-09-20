#!/usr/bin/env python3
"""Small host-only entry point for the checklist-driven recon workflow."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from bb_harness.cli.repl import HarnessREPL


def read_targets(value: str) -> list[str]:
    path = Path(value)
    if path.is_file():
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    return [part.strip() for part in value.split(",") if part.strip()]


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run authorized bb-harness recon on the Linux host."
    )
    parser.add_argument(
        "target",
        help="domain, wildcard root, comma-separated domains, or a newline-delimited file",
    )
    args = parser.parse_args()

    targets = read_targets(args.target)
    if not targets:
        raise SystemExit("No targets supplied.")

    for target in targets:
        repl = HarnessREPL()
        await repl.run_headless(
            target=target,
            mode="host",
            agents="all",
            export_fmt="json",
        )


if __name__ == "__main__":
    asyncio.run(main())
