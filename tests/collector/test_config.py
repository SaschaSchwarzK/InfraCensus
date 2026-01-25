import os
import unittest

from collector.core.config import CollectorConfig


class TestCollectorConfig(unittest.TestCase):
    def test_invalid_central_url(self):
        original = os.environ.get("CENTRAL_URL")
        try:
            os.environ["CENTRAL_URL"] = "central.local"
            with self.assertRaises(ValueError):
                CollectorConfig.from_env()
        finally:
            if original is None:
                os.environ.pop("CENTRAL_URL", None)
            else:
                os.environ["CENTRAL_URL"] = original


if __name__ == "__main__":
    unittest.main()
