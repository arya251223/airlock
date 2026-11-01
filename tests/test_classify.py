import unittest
from app.core.classify import tripped_limits as t


class ClassifyTests(unittest.TestCase):
    def test_timeout(self):
        self.assertEqual(t("timeout", "", "", False, "clean"), ["time"])

    def test_memory_error_text(self):
        self.assertEqual(t("error", "Traceback...\nMemoryError", "", False, "clean"), ["memory"])

    def test_oom(self):
        self.assertIn("memory", t("oom_killed", "", "", False, "clean"))

    def test_network(self):
        self.assertEqual(t("error", "OSError: [Errno 101] Network is unreachable", "", False, "clean"), ["network"])

    def test_filesystem_and_dedupe(self):
        r = t("error", "OSError: [Errno 30] Read-only file system\nPermission denied", "", False, "clean")
        self.assertEqual(r, ["filesystem"])

    def test_output_and_policy(self):
        self.assertEqual(t("blocked", "", "", False, "blocked"), ["policy"])
        self.assertEqual(t("success", "", "", True, "clean"), ["output"])

    def test_plain_success_trips_nothing(self):
        self.assertEqual(t("success", "", "42", False, "clean"), [])


if __name__ == "__main__":
    unittest.main()
