"""Safe family-level tool selection for checklist execution.

This router only describes eligible adapters. It does not install tools and it
does not execute gated adapters; callers must enforce the returned policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ToolRouter:
    def __init__(self, manifest_path: str | Path = "tools/tool-manifest.json"):
        self.path = Path(manifest_path)
        self.data: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))

    def route(self, family: str) -> dict[str, Any]:
        key = family.lower().replace(" ", "_").replace("&", "and")
        families = self.data.get("families", {})
        selected = families.get(key)
        if selected:
            return {"family": key, **selected}
        return {"family": key, "tools": [], "safe": False, "manual": True, "reason": "No family adapter registered"}

    def inventory(self) -> dict[str, list[str]]:
        return self.data.get("observed_in_image", {"present": [], "missing_or_unverified": []})
