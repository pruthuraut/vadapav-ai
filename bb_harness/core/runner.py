"""Host-only execution engine for installed recon tools."""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import List

from bb_harness.core.config import OUTPUT_DIR


class ToolResult:
    """Result from a local command."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0,
                 success: bool = True, tool: str = "", mode: str = "host"):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.success = success
        self.tool = tool
        self.mode = mode

    @property
    def output(self) -> str:
        return self.stdout.strip()

    @property
    def lines(self) -> List[str]:
        return [line.strip() for line in self.stdout.splitlines() if line.strip()]


class HostRunner:
    """Run commands installed on the Linux host."""

    @staticmethod
    def is_available(tool: str) -> bool:
        return shutil.which(tool) is not None

    @staticmethod
    async def run(cmd: str, timeout: int = 300, cwd: str | None = None) -> ToolResult:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd or str(OUTPUT_DIR),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return ToolResult(
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                proc.returncode or 0,
                proc.returncode == 0,
                cmd.split()[0] if cmd else "",
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return ToolResult(stderr=f"Command timed out after {timeout}s: {cmd}", returncode=-1, success=False)
        except Exception as exc:
            return ToolResult(stderr=str(exc), returncode=-1, success=False)

    @staticmethod
    def run_sync(cmd: str, timeout: int = 300, cwd: str | None = None) -> ToolResult:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, cwd=cwd or str(OUTPUT_DIR),
            )
            return ToolResult(result.stdout, result.stderr, result.returncode, result.returncode == 0)
        except Exception as exc:
            return ToolResult(stderr=str(exc), returncode=-1, success=False)


class DualRunner:
    """Compatibility name retained for the agents; execution is host-only."""

    def __init__(self, mode: str = "host"):
        self.mode = "host"
        self.host = HostRunner()

    async def run_tool(self, tool_name: str, cmd: str,
                       timeout: int = 300, fallback: bool = True) -> ToolResult:
        if not self.host.is_available(tool_name):
            return ToolResult(
                stderr=f"Tool '{tool_name}' is not installed on the host",
                returncode=-1, success=False, tool=tool_name,
            )
        return await self.host.run(cmd, timeout=timeout)

    async def run_python(self, cmd: str, timeout: int = 300) -> ToolResult:
        return await self.host.run(f"python3 -c \"{cmd}\"", timeout=timeout)
