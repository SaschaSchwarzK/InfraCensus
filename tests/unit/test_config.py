import os

import pytest

from central.core.config import Settings


def test_session_secret_validation():
    os.environ.pop("SESSION_SECRET", None)
    os.environ.pop("CENTRAL_SESSION_SECRET", None)
    with pytest.raises(ValueError, match="SESSION_SECRET"):
        Settings.from_sources(
            {
                "environment": "prod",
                "session_secret": "weak",
            }
        )


def test_port_validation():
    with pytest.raises(ValueError, match="api_port"):
        Settings.from_sources(
            {
                "environment": "dev",
                "api_port": 99999,
            }
        )
