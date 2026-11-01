import unittest
from app.core.policy import analyze


class PolicyTests(unittest.TestCase):
    def test_clean_code(self):
        r = analyze("print(sum(range(10)))", "warn")
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.findings, [])

    def test_socket_import_flagged_in_warn_mode(self):
        r = analyze("import socket\n", "warn")
        self.assertEqual(r.verdict, "flagged")
        self.assertEqual(r.findings[0].category, "network")
        self.assertEqual(r.findings[0].line, 1)

    def test_subprocess_blocked_in_block_mode(self):
        r = analyze("import subprocess\nsubprocess.run(['ls'])", "block")
        self.assertEqual(r.verdict, "blocked")

    def test_medium_severity_not_blocked(self):
        r = analyze("import urllib.request", "block")
        self.assertEqual(r.verdict, "flagged")  # medium only -> reported, not blocked

    def test_os_system_call(self):
        r = analyze("import os\nos.system('id')", "block")
        self.assertEqual(r.verdict, "blocked")
        self.assertTrue(any("os.system" in f.message for f in r.findings))

    def test_from_os_import_system(self):
        self.assertEqual(analyze("from os import system", "block").verdict, "blocked")

    def test_dunder_import_flagged(self):
        r = analyze("__import__('so'+'cket')", "warn")
        self.assertEqual(r.findings[0].category, "obfuscation")

    def test_syntax_error_reported_not_raised(self):
        r = analyze("def (:", "block")
        self.assertEqual(r.verdict, "syntax_error")

    def test_off_mode_skips_analysis(self):
        self.assertEqual(analyze("import socket", "off").verdict, "clean")

    def test_known_limitation_obfuscation_is_not_caught(self):
        # Documented limitation: the static layer is advisory. getattr tricks evade it,
        # which is exactly why the container is the real boundary.
        r = analyze("m = __import__('o' + 's')\ngetattr(m, 'sys' + 'tem')('id')", "block")
        self.assertNotEqual(r.verdict, "blocked")


if __name__ == "__main__":
    unittest.main()
