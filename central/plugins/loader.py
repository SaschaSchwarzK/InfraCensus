from __future__ import annotations

import importlib
import re
from collections.abc import Iterable


def load_plugins(module_paths: Iterable[str]) -> None:
    # Define allowed module path pattern (alphanumeric, dots, underscores)
    allowed_pattern = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]*$")

    for module_path in module_paths:
        # Validate module path to prevent code injection
        if not isinstance(module_path, str):
            raise ValueError(f"Module path must be a string, got {type(module_path)}")

        if not allowed_pattern.match(module_path):
            raise ValueError(f"Invalid module path format: {module_path}")

        # Additional safety check - prevent relative imports and system modules
        if module_path.startswith(".") or module_path in ("os", "sys", "subprocess"):
            raise ValueError(f"Prohibited module path: {module_path}")

        try:
            importlib.import_module(module_path)
        except ImportError as exc:
            raise ImportError(
                f"Failed to load plugin module '{module_path}': {exc}"
            ) from exc
