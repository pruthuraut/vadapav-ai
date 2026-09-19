"""Safe, read-only revalidation of triage observations."""
import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import httpx


def expected_headers(text: str) -> list[str]:
    low = text.lower()
    mapping = {
        "httponly": "set-cookie",
        "samesite": "set-cookie",
        "secure flag": "set-cookie",
        "hsts": "strict-transport-security",
        "content-security-policy": "content-security-policy",
        "x-frame": "x-frame-options",
        "referrer-policy": "referrer-policy",
        "x-content-type": "x-content-type-options",
    }
    return sorted({value for key, value in mapping.items() if key in low})


def cookie_control(text: str) -> str:
    low = text.lower()
    if "httponly" in low:
        return "httponly"
    if "samesite" in low:
        return "samesite"
    if "secure flag" in low or "secure cookies" in low:
        return "secure"
    return ""


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", default="output/reports/validation_latest.json")
    args = parser.parse_args()
    triage = json.loads(Path(args.input).read_text(encoding="utf-8"))
    root = args.target.lower().strip().lstrip("*.").rstrip(".")
    items = triage.get("needs_review", [])
    results = []
    seen = set()
    async with httpx.AsyncClient(timeout=15, follow_redirects=False, verify=False, headers={"User-Agent": "bb-harness-safe-validator/1.0"}) as client:
        for item in items:
            url = item.get("target", "")
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            key = (item.get("checklist_text", ""), url)
            if key in seen:
                continue
            seen.add(key)
            result = {"check_ids": item.get("check_ids", []), "checklist_text": item.get("checklist_text", ""), "target": url, "status": "inconclusive", "evidence": {}}
            if parsed.scheme not in {"http", "https"} or not (host == root or host.endswith("." + root)):
                result["status"] = "out_of_scope"
                results.append(result)
                continue
            try:
                response = await client.get(url)
                original_status = response.status_code
                original_location = response.headers.get("location", "")
                if response.is_redirect and original_location:
                    redirected = httpx.URL(original_location, base=url)
                    redirect_host = (redirected.host or "").lower().rstrip(".")
                    if redirected.scheme in {"http", "https"} and (redirect_host == root or redirect_host.endswith("." + root)):
                        response = await client.get(str(redirected))
                headers = {k.lower(): v for k, v in response.headers.items()}
                expected = expected_headers(result["checklist_text"])
                control = cookie_control(result["checklist_text"])
                if control:
                    raw_cookies = response.headers.get_list("set-cookie")
                    if not raw_cookies:
                        result["status"] = "inconclusive"
                        result["evidence"] = {"status_code": response.status_code, "reason": "No Set-Cookie header was issued; cookie flag cannot be assessed."}
                    else:
                        missing = [cookie for cookie in raw_cookies if control not in cookie.lower()]
                        result["status"] = "reproduced" if missing else "not_reproduced"
                        result["evidence"] = {"status_code": response.status_code, "cookie_count": len(raw_cookies), "control": control, "cookies_missing_control": len(missing)}
                else:
                    missing = [header for header in expected if header not in headers]
                    result["evidence"] = {"original_status": original_status, "final_status": response.status_code, "expected_headers": expected, "missing_headers": missing, "original_location": original_location, "final_url": str(response.url)}
                    result["status"] = "reproduced" if expected and missing else ("not_reproduced" if expected else "inconclusive")
            except Exception as exc:
                result["evidence"] = {"error": str(exc)[:200]}
            results.append(result)
    summary = {"total": len(results), "reproduced": sum(r["status"] == "reproduced" for r in results), "not_reproduced": sum(r["status"] == "not_reproduced" for r in results), "inconclusive": sum(r["status"] == "inconclusive" for r in results), "out_of_scope": sum(r["status"] == "out_of_scope" for r in results)}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"target": root, "summary": summary, "results": results, "note": "Reproduced means the observed control condition was seen again; it is not a confirmed vulnerability without contextual/manual review."}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(str(output.resolve()))


if __name__ == "__main__":
    asyncio.run(main())
