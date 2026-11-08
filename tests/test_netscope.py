import unittest
from unittest.mock import patch
from netscope import parse_ports, check_port

class TestNetScope(unittest.TestCase):
    def test_parse_single_and_range(self):
        self.assertEqual(parse_ports("22,80,443,8000-8002"),
                         [22, 80, 443, 8000, 8001, 8002])

    def test_parse_deduplicates_and_sorts(self):
        self.assertEqual(parse_ports("80,22,80"), [22, 80])

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("0,80")

    def test_rejects_large_scan(self):
        with self.assertRaises(ValueError):
            parse_ports("1-257")

    @patch("netscope.socket.create_connection")
    def test_open_port(self, mock_connect):
        mock_connect.return_value.__enter__.return_value = None
        self.assertTrue(check_port("127.0.0.1", 80))
        mock_connect.assert_called_once()

    @patch("netscope.socket.create_connection", side_effect=OSError)
    def test_closed_port(self, _mock_connect):
        self.assertFalse(check_port("127.0.0.1", 81))

if __name__ == "__main__":
    unittest.main()
