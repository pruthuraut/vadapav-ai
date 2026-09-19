"""
bb_harness.core.runner
Dual execution engine: HostRunner for local tools (with fallbacks) and ContainerRunner for Docker.
"""
import asyncio
import shutil
import subprocess
import sys
import os
from typing import Optional, List, Tuple
from pathlib import Path

from bb_harness.core.config import DOCKER_IMAGE, CONTAINER_WORKSPACE, OUTPUT_DIR, BASE_DIR


class ToolResult:
    """Result from running a tool."""
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
        return [l.strip() for l in self.stdout.strip().splitlines() if l.strip()]


class HostRunner:
    """Runs tools natively on the host machine."""

    @staticmethod
    def is_available(tool: str) -> bool:
        """Check if a CLI tool is available on PATH."""
        return shutil.which(tool) is not None

    @staticmethod
    async def run(cmd: str, timeout: int = 300, cwd: str = None) -> ToolResult:
        """Run a command asynchronously and return the result."""
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd or str(OUTPUT_DIR),
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd or str(OUTPUT_DIR),
                )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return ToolResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                returncode=proc.returncode or 0,
                success=(proc.returncode == 0),
                tool=cmd.split()[0] if cmd else "",
                mode="host",
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return ToolResult(
                stderr=f"Command timed out after {timeout}s: {cmd}",
                returncode=-1,
                success=False,
                tool=cmd.split()[0] if cmd else "",
                mode="host",
            )
        except Exception as e:
            return ToolResult(
                stderr=str(e),
                returncode=-1,
                success=False,
                tool=cmd.split()[0] if cmd else "",
                mode="host",
            )

    @staticmethod
    def run_sync(cmd: str, timeout: int = 300, cwd: str = None) -> ToolResult:
        """Run a command synchronously."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd or str(OUTPUT_DIR),
            )
            return ToolResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                success=(result.returncode == 0),
                tool=cmd.split()[0] if cmd else "",
                mode="host",
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                stderr=f"Command timed out after {timeout}s",
                returncode=-1,
                success=False,
                tool=cmd.split()[0] if cmd else "",
                mode="host",
            )
        except Exception as e:
            return ToolResult(
                stderr=str(e),
                returncode=-1,
                success=False,
                tool=cmd.split()[0] if cmd else "",
                mode="host",
            )


class ContainerRunner:
    """Runs tools inside a Docker container."""

    @staticmethod
    def is_docker_available() -> bool:
        """Check if Docker is available and running."""
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def image_exists() -> bool:
        """Check if the bb-harness Docker image exists."""
        try:
            result = subprocess.run(
                ["docker", "images", "-q", DOCKER_IMAGE],
                capture_output=True, text=True, timeout=10,
            )
            return bool(result.stdout.strip())
        except Exception:
            return False

    @staticmethod
    def build_image() -> ToolResult:
        """Build the Docker image from Dockerfile."""
        dockerfile_path = BASE_DIR / "Dockerfile"
        if not dockerfile_path.exists():
            return ToolResult(
                stderr="Dockerfile not found",
                returncode=-1,
                success=False,
                mode="container",
            )
        try:
            result = subprocess.run(
                ["docker", "build", "-t", DOCKER_IMAGE, str(BASE_DIR)],
                capture_output=True, text=True, timeout=600,
            )
            return ToolResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                success=(result.returncode == 0),
                mode="container",
            )
        except Exception as e:
            return ToolResult(
                stderr=str(e), returncode=-1, success=False, mode="container"
            )

    @staticmethod
    async def run(cmd: str, timeout: int = 300, volumes: dict = None) -> ToolResult:
        """Run a command inside the Docker container."""
        vol_args = []
        if volumes:
            for host_path, container_path in volumes.items():
                vol_args.extend(["-v", f"{host_path}:{container_path}"])
        else:
            # Default: mount output dir
            vol_args = ["-v", f"{OUTPUT_DIR}:{CONTAINER_WORKSPACE}"]

        docker_cmd = [
            "docker", "run", "--rm", "--network=host",
            *vol_args,
            "-w", CONTAINER_WORKSPACE,
            DOCKER_IMAGE,
            "sh", "-c", cmd,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return ToolResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                returncode=proc.returncode or 0,
                success=(proc.returncode == 0),
                tool=cmd.split()[0] if cmd else "",
                mode="container",
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return ToolResult(
                stderr=f"Container command timed out after {timeout}s",
                returncode=-1,
                success=False,
                mode="container",
            )
        except Exception as e:
            return ToolResult(
                stderr=str(e), returncode=-1, success=False, mode="container"
            )


class DualRunner:
    """
    Unified runner: tries host first, falls back to container (or vice versa
    based on user preference).
    """

    def __init__(self, mode: str = "host"):
        self.mode = mode
        self.host = HostRunner()
        self.container = ContainerRunner()

    async def run_tool(self, tool_name: str, cmd: str,
                       timeout: int = 300, fallback: bool = True) -> ToolResult:
        """Run a tool in the preferred mode, with optional fallback."""
        if self.mode == "host":
            if self.host.is_available(tool_name):
                result = await self.host.run(cmd, timeout=timeout)
                if result.success:
                    return result
            if fallback and self.container.is_docker_available():
                return await self.container.run(cmd, timeout=timeout)
            # Tool not available in any mode
            return ToolResult(
                stderr=f"Tool '{tool_name}' not found on host and container not available",
                returncode=-1,
                success=False,
                tool=tool_name,
                mode="host",
            )
        else:  # container mode
            if self.container.is_docker_available():
                result = await self.container.run(cmd, timeout=timeout)
                if result.success:
                    return result
            if fallback and self.host.is_available(tool_name):
                return await self.host.run(cmd, timeout=timeout)
            return ToolResult(
                stderr=f"Container not available and tool '{tool_name}' not found on host",
                returncode=-1,
                success=False,
                tool=tool_name,
                mode="container",
            )

    async def run_python(self, cmd: str, timeout: int = 300) -> ToolResult:
        """Always run via host Python (for built-in fallback methods)."""
        return await self.host.run(f"{sys.executable} -c \"{cmd}\"", timeout=timeout)
