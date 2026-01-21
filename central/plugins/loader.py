from __future__ import annotations

import importlib
from typing import Iterable


def load_plugins(module_paths: Iterable[str]) -> None:
    for module_path in module_paths:
        importlib.import_module(module_path)
