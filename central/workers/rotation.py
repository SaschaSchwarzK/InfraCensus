from __future__ import annotations

import asyncio
import logging
import os
import secrets
import string
from typing import Any

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.core.vault import VaultClient, VaultSettings


def _generate_secret(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@celery_app.task(name="workers.rotate_credentials")
def rotate_credentials_task() -> dict[str, Any]:
    addr = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    mount = os.getenv("VAULT_KV_MOUNT", "secret")
    namespace = os.getenv("VAULT_NAMESPACE")
    targets = os.getenv("VAULT_ROTATION_TARGETS", "")
    if not addr or not token or not targets:
        log_warning(
            logging.getLogger(__name__),
            "rotation.skipped",
            reason="missing_vault_or_targets",
        )
        return {"status": "skipped"}
    rotated = asyncio.run(
        _rotate_credentials(
            addr=addr,
            token=token,
            mount=mount,
            namespace=namespace,
            targets=[item.strip() for item in targets.split(",") if item.strip()],
        )
    )
    log_info(logging.getLogger(__name__), "rotation.completed", rotated=rotated)
    return {"status": "ok", "rotated": rotated}


async def _rotate_credentials(
    *, addr: str, token: str, mount: str, namespace: str | None, targets: list[str]
) -> int:
    rotated = 0
    async with VaultClient(
        VaultSettings(addr=addr, token=token, kv_mount=mount, namespace=namespace)
    ) as client:
        for path in targets:
            payload = {"secret": _generate_secret()}
            if await client.write_secret(path, payload):
                rotated += 1
    return rotated
