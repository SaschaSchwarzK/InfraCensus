from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)
_GIT_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


@dataclass(frozen=True)
class ConfigSource:
    config_file: str | None
    git_url: str | None
    git_ref: str | None
    git_path: str | None
    git_dir: str | None

    @classmethod
    def from_env(cls) -> ConfigSource:
        config_file = _env("CONFIG_FILE")
        git_url = _env("CONFIG_GIT_URL")
        git_ref = _env("CONFIG_GIT_REF", "main")
        git_path = _env("CONFIG_GIT_PATH", "config/collector.yaml")
        git_dir = _env("CONFIG_GIT_DIR", "/tmp/infracensus-config")
        return cls(
            config_file=config_file,
            git_url=git_url,
            git_ref=git_ref,
            git_path=git_path,
            git_dir=git_dir,
        )

    async def load(self) -> tuple[dict[str, Any], str | None]:
        config_path = await self._resolve_path()
        if not config_path:
            return {}, None
        if not config_path.exists():
            logger.warning("config.source_missing", extra={"path": str(config_path)})
            return {}, None
        content = config_path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        payload = yaml.safe_load(content) or {}
        if not isinstance(payload, dict):
            raise ValueError("Config file must contain a mapping at top-level.")
        return payload, digest

    async def _resolve_path(self) -> Path | None:
        if self.git_url:
            await self._ensure_repo()
            await self._update_repo()
            if not self.git_dir or not self.git_path:
                return None
            return Path(self.git_dir) / self.git_path
        if self.config_file:
            return Path(self.config_file)
        return None

    async def _ensure_repo(self) -> None:
        if not self.git_dir:
            raise RuntimeError("CONFIG_GIT_DIR is required when CONFIG_GIT_URL is set")
        repo_dir = Path(self.git_dir)
        if repo_dir.exists() and (repo_dir / ".git").exists():
            return
        if repo_dir.exists():
            raise RuntimeError(
                f"CONFIG_GIT_DIR exists but is not a git repo: {repo_dir}"
            )
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        if not self.git_url:
            raise RuntimeError("CONFIG_GIT_URL is required when using git config")
        git_url = _validate_git_url(self.git_url)
        await self._run_git(
            ["clone", "--depth", "1", git_url, str(repo_dir)]
        )

    async def _update_repo(self) -> None:
        if not self.git_dir:
            return
        repo_dir = Path(self.git_dir)
        if not repo_dir.exists():
            return
        if not self.git_ref:
            return
        git_ref = _validate_git_ref(self.git_ref)
        await self._run_git(
            ["fetch", "--depth", "1", "origin", git_ref], cwd=repo_dir
        )
        await self._run_git(["reset", "--hard", f"origin/{git_ref}"], cwd=repo_dir)

    async def _run_git(self, args: list[str], cwd: Path | None = None) -> None:
        if not _validate_git_args(args):
            raise ValueError("Invalid git command")
        
        # Validate git arguments to prevent command injection
        safe_args = []
        for arg in args:
            if not isinstance(arg, str):
                raise ValueError(f"Invalid git argument type: {type(arg)}")
            # Remove dangerous characters that could be used for injection
            if any(char in arg for char in [";", "&", "|", "`", "$", "\n", "\r"]):
                raise ValueError(f"Unsafe git argument: {arg}")
            safe_args.append(arg)
        
        process = await asyncio.create_subprocess_exec(
            "git",
            *safe_args,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(
                "config.git_failed",
                extra={
                    "args": " ".join(safe_args),
                    "stdout": (stdout or b"").decode().strip(),
                    "stderr": (stderr or b"").decode().strip(),
                },
            )
            raise RuntimeError("Git command failed")


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"COLLECTOR_{name}") or os.getenv(name) or default


def _validate_git_url(value: str) -> str:
    candidate = value.strip()
    if not candidate or candidate.startswith("-") or any(ch.isspace() for ch in candidate):
        raise ValueError("Invalid CONFIG_GIT_URL")
    parsed = urlparse(candidate)
    if parsed.scheme in {"http", "https", "ssh"}:
        return candidate
    if ":" in candidate and "/" in candidate and not candidate.startswith("/"):
        return candidate
    raise ValueError("Unsupported CONFIG_GIT_URL scheme")


def _validate_git_ref(value: str) -> str:
    candidate = value.strip()
    if not candidate or candidate.startswith("-"):
        raise ValueError("Invalid CONFIG_GIT_REF")
    if not _GIT_REF_RE.fullmatch(candidate):
        raise ValueError("Invalid CONFIG_GIT_REF")
    return candidate


def _validate_git_args(args: list[str]) -> bool:
    if not args:
        return False
    cmd = args[0]
    if cmd == "clone":
        return args[:3] == ["clone", "--depth", "1"] and len(args) == 5
    if cmd == "fetch":
        return args[:3] == ["fetch", "--depth", "1"] and len(args) == 5
    if cmd == "reset":
        return args[:2] == ["reset", "--hard"] and len(args) == 3
    return False
