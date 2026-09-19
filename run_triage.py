"""Conservative triage for a guarded hunt report."""
import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="output/reports/triage_latest.json")
    parser.add_argument("--target", default="")
    args = parser.parse_args()
    report = json.loads(Path(args.input).read_text(encoding="utf-8"))
    groups = defaultdict(list)
    for item in report.get("results", []):
        for evidence in item.get("evidence", []):
            if evidence.get("new_findings", 0) > 0:
                groups[(item.get("checklist_text", ""), evidence.get("target", ""))].append(item.get("check_id"))
    needs_review = []
    for (text, target), ids in sorted(groups.items()):
        needs_review.append({"check_ids": sorted(set(ids)), "checklist_text": text, "target": target, "state": "needs_review", "confidence": "preliminary", "reason": "Automated observation requires manual reproduction against the specific checklist item."})
    approval = [r for r in report.get("results", []) if r.get("status") in ("approval_required", "blocked")]
    target = report.get("context", {}).get("target") or args.target
    triage = {"generated_at": datetime.utcnow().isoformat(), "session_id": report.get("context", {}).get("session_id"), "target": target, "confirmed": [], "needs_review": needs_review, "approval_queue_count": len(approval), "note": "No confirmed vulnerabilities were produced automatically. Validate scope, reproduce safely, and attach sanitized request/response evidence before reporting."}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(triage, indent=2), encoding="utf-8")
    md = output.with_suffix(".md")
    lines = [f"# Triage Report: {triage.get('target') or 'unknown'}", "", f"Generated: {triage['generated_at']}", "", "## Summary", "", "| Queue | Count |", "|---|---:|", f"| Confirmed | 0 |", f"| Needs review | {len(needs_review)} |", f"| Approval/blocked | {len(approval)} |", "", "## Needs review", "", "| Checklist item | Target | State |", "|---|---|---|"]
    for item in needs_review:
        checklist_text = item["checklist_text"].replace("|", "\\|")
        lines.append(f"| {checklist_text} | `{item['target']}` | `{item['state']}` |")
    lines += ["", "## Validation rule", "", triage["note"]]
    md.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"confirmed": 0, "needs_review": len(needs_review), "approval_queue": len(approval), "json": str(output), "markdown": str(md)}, indent=2))


if __name__ == "__main__":
    main()
