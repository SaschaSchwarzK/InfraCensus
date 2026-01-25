import unittest

from collector.utils.network import is_valid_target


class TestNetworkUtils(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(is_valid_target("192.168.1.1"))

    def test_valid_cidr(self):
        self.assertTrue(is_valid_target("10.0.0.0/24"))

    def test_valid_hostname(self):
        self.assertTrue(is_valid_target("router-01.example"))

    def test_invalid_target(self):
        self.assertFalse(is_valid_target("not a host"))


if __name__ == "__main__":
    unittest.main()
