"""Run the guarded post-recon checklist coordinator."""
import argparse
import asyncio
import json
from datetime import datetime
from pathlib import Path

from bb_harness.agents.attack_phase import AttackPhaseAgent
from bb_harness.agents.security_testing import load_har
from bb_harness.core.db import Database
from bb_harness.core.runner import DualRunner


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--checklist", default="security-checklist.txt")
    parser.add_argument("--har", default="")
    parser.add_argument("--output", default="output/reports/attack_phase_report.json")
    args = parser.parse_args()
    traffic = load_har(args.har) if args.har else []
    agent = AttackPhaseAgent(Database(), DualRunner(mode="container"), args.session, args.checklist, traffic)
    report = await agent.start()
    report["generated_at"] = datetime.utcnow().isoformat()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(str(output.resolve()))


if __name__ == "__main__":
    asyncio.run(main())
