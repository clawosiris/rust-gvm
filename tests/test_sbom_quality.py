import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from scripts.check_sbom_quality import check_report, main


class SbomQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="sbom-quality-"))
        self.addCleanup(shutil.rmtree, self.temp_dir)

    def write_report(self, report: object) -> Path:
        path = self.temp_dir / "report.json"
        path.write_text(json.dumps(report))
        return path

    def test_current_sbomqs_schema_passes_at_threshold(self) -> None:
        failures = check_report(
            {
                "files": [
                    {
                        "file_name": "gvm-client.cdx.json",
                        "sbom_quality_score": 8.3,
                    }
                ]
            },
            8.3,
        )

        self.assertEqual(failures, [])

    def test_legacy_schema_remains_supported(self) -> None:
        failures = check_report(
            {"files": [{"path": "legacy.cdx.json", "avg_score": 8.4}]},
            8.3,
        )

        self.assertEqual(failures, [])

    def test_below_threshold_is_blocking(self) -> None:
        report = self.write_report(
            {
                "files": [
                    {
                        "file_name": "gvm-gmp.cdx.json",
                        "sbom_quality_score": 8.29,
                    }
                ]
            }
        )

        output = StringIO()
        with redirect_stdout(output):
            exit_code = main(["--threshold", "8.3", str(report)])

        self.assertEqual(exit_code, 1)
        self.assertIn("::error file=gvm-gmp.cdx.json::", output.getvalue())

    def test_missing_scores_fail_closed(self) -> None:
        report = self.write_report({"files": [{"file_name": "missing.cdx.json"}]})

        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([str(report)])

        self.assertEqual(exit_code, 2)
        self.assertIn("score is missing or non-numeric", output.getvalue())

    def test_boolean_and_out_of_range_scores_fail_closed(self) -> None:
        reports = [
            ({"files": [{"sbom_quality_score": True}]}, "score must be numeric"),
            ({"files": [{"sbom_quality_score": 10.1}]}, "between 0 and 10"),
        ]

        for report, expected in reports:
            with self.subTest(report=report):
                output = StringIO()
                with redirect_stdout(output):
                    exit_code = main([str(self.write_report(report))])
                self.assertEqual(exit_code, 2)
                self.assertIn(expected, output.getvalue())

    def test_non_object_report_and_file_entry_fail_closed(self) -> None:
        reports = [([], "must be a JSON object"), ({"files": [None]}, "files[0]")]

        for report, expected in reports:
            with self.subTest(report=report):
                output = StringIO()
                with redirect_stdout(output):
                    exit_code = main([str(self.write_report(report))])
                self.assertEqual(exit_code, 2)
                self.assertIn(expected, output.getvalue())

    def test_invalid_threshold_is_rejected(self) -> None:
        report = self.write_report({"files": [{"sbom_quality_score": 8.3}]})

        with (
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
            self.assertRaises(SystemExit),
        ):
            main(["--threshold", "11", str(report)])

    def test_empty_report_fails_closed(self) -> None:
        report = self.write_report({"files": []})

        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([str(report)])

        self.assertEqual(exit_code, 2)
        self.assertIn("contains no scored files", output.getvalue())


if __name__ == "__main__":  # pragma: no cover - unittest invokes the module
    unittest.main()
