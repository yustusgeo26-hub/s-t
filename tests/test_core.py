import unittest

from modules.dorking import build_dorks
from modules.email_lookup import analyze_email
from modules.leak_lookup import password_pwned_count
from yustus import menu_lines


class TestYustusCore(unittest.TestCase):
    def test_dork_generation(self):
        result = build_dorks("example.com")
        self.assertEqual(result["target"], "example.com")
        self.assertGreaterEqual(len(result["dorks"]), 8)

    def test_invalid_email(self):
        result = analyze_email("not-an-email")
        self.assertFalse(result["valid"])
        self.assertIn("error", result)

    def test_empty_password(self):
        result = password_pwned_count("")
        self.assertIn("error", result)

    def test_menu_has_expected_entries(self):
        lines = menu_lines()
        self.assertIn("1 Username Intelligence (Sherlock style, 300+ sites)", lines)
        self.assertIn("13 Exit", lines)


if __name__ == "__main__":
    unittest.main()
