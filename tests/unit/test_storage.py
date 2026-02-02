from __future__ import annotations

import pytest

from collector.core.storage import LocalStorage


def test_storage_save_and_load(tmp_path) -> None:
    storage = LocalStorage(str(tmp_path))
    storage.save_json("data.json", {"a": 1})
    assert storage.load_json("data.json") == {"a": 1}


def test_storage_update_json(tmp_path) -> None:
    storage = LocalStorage(str(tmp_path))
    storage.save_json("data.json", {"a": 1})
    updated = storage.update_json("data.json", {"b": 2})
    assert updated == {"a": 1, "b": 2}


def test_storage_rejects_traversal(tmp_path) -> None:
    storage = LocalStorage(str(tmp_path))
    with pytest.raises(ValueError, match="path traversal"):
        storage.save_json("../secret.json", {"a": 1})
