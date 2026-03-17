import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.sbom_postprocess import main, transform_sbom


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sbom" / "minimal.cdx.json"


class SbomPostprocessTests(unittest.TestCase):
    def test_transform_injects_metadata_and_suppliers(self) -> None:
        document = json.loads(FIXTURE.read_text())

        transformed = transform_sbom(document, workspace_supplier="clawosiris")

        self.assertEqual(transformed["specVersion"], "1.5")
        self.assertEqual(
            transformed["metadata"]["licenses"],
            [{"license": {"id": "CC0-1.0"}}],
        )
        self.assertEqual(
            transformed["metadata"]["lifecycles"],
            [{"phase": "build"}],
        )
        self.assertEqual(
            transformed["metadata"]["component"]["supplier"],
            {"name": "clawosiris"},
        )
        self.assertEqual(
            transformed["components"][0]["supplier"],
            {"name": "clawosiris"},
        )
        self.assertEqual(
            transformed["components"][1]["supplier"],
            {"name": "crates.io"},
        )

    def test_script_overwrites_input_file(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="sbom-postprocess-"))
        self.addCleanup(shutil.rmtree, temp_dir)

        sbom_path = temp_dir / "input.cdx.json"
        sbom_path.write_text(FIXTURE.read_text())

        exit_code = main(
            ["--cargo-toml", str(ROOT / "Cargo.toml"), str(sbom_path)]
        )

        self.assertEqual(exit_code, 0)
        transformed = json.loads(sbom_path.read_text())
        self.assertEqual(transformed["metadata"]["licenses"][0]["license"]["id"], "CC0-1.0")


if __name__ == "__main__":
    unittest.main()
