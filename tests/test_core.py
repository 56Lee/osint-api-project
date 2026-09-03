import unittest
from unittest.mock import patch

from core.get_exploitsfile import ExploitSearcher
from core.make_report import generate_pdf_report
from main import analyze_services, resolve_target


class VersionParsingTests(unittest.TestCase):
    def test_extracts_version_from_banner(self):
        self.assertEqual(str(ExploitSearcher.parse_version("OpenSSH_9.6p1")), "9.6")

    def test_rejects_missing_version(self):
        self.assertIsNone(ExploitSearcher.parse_version("unknown"))


class TargetResolutionTests(unittest.TestCase):
    @patch("main.socket.gethostbyname", return_value="203.0.113.10")
    def test_accepts_url_and_strips_port(self, resolver):
        self.assertEqual(resolve_target("https://example.com:8443/path"), "203.0.113.10")
        resolver.assert_called_once_with("example.com")


class AnalysisTests(unittest.TestCase):
    def test_lookup_failure_requires_manual_review(self):
        searcher = unittest.mock.Mock()
        searcher.search_exploits.return_value = None
        findings = analyze_services([{"port": 443, "product": "nginx", "version": "1.0"}], searcher)
        self.assertEqual(findings[0]["status"], "Manual Check")


class ReportTests(unittest.TestCase):
    @patch("core.make_report.FPDF.output")
    def test_sanitizes_report_filename(self, output):
        path = generate_pdf_report("../bad target", [])
        self.assertTrue(path.endswith("bad_target_report.pdf"))
        self.assertNotIn("..", path.split("output")[-1])
        output.assert_called_once()


if __name__ == "__main__":
    unittest.main()
