from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConfigSource:
    config_file: str | None
    git_url: str | None
    git_ref: str
    git_path: str
    git_dir: str

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
            logger.warning("config.source_missing", path=str(config_path))
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
            return Path(self.git_dir) / self.git_path
        if self.config_file:
            return Path(self.config_file)
        return None

    async def _ensure_repo(self) -> None:
        repo_dir = Path(self.git_dir)
        if repo_dir.exists() and (repo_dir / ".git").exists():
            return
        if repo_dir.exists():
            raise RuntimeError(
                f"CONFIG_GIT_DIR exists but is not a git repo: {repo_dir}"
            )
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        await self._run_git(
            ["clone", "--depth", "1", self.git_url or "", str(repo_dir)]
        )

    async def _update_repo(self) -> None:
        repo_dir = Path(self.git_dir)
        if not repo_dir.exists():
            return
        await self._run_git(
            ["fetch", "--depth", "1", "origin", self.git_ref], cwd=repo_dir
        )
        await self._run_git(["reset", "--hard", f"origin/{self.git_ref}"], cwd=repo_dir)

    async def _run_git(self, args: list[str], cwd: Path | None = None) -> None:
        if not args or not args[0]:
            raise ValueError("Invalid git command")
        process = await asyncio.create_subprocess_exec(
            "git",
            *args,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(
                "config.git_failed",
                args=" ".join(args),
                stdout=(stdout or b"").decode().strip(),
                stderr=(stderr or b"").decode().strip(),
            )
            raise RuntimeError("Git command failed")


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"COLLECTOR_{name}") or os.getenv(name) or default
