import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.sbom_postprocess import (
    ensure_dependency_completeness,
    main,
    transform_sbom,
)


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
            transformed["metadata"]["authors"],
            [{"name": "clawosiris"}],
        )
        self.assertEqual(
            transformed["metadata"]["supplier"],
            {"name": "clawosiris"},
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
        nested = transformed["metadata"]["component"]["components"][0]
        self.assertEqual(nested["licenses"], [{"expression": "AGPL-3.0-or-later"}])
        self.assertEqual(
            nested["externalReferences"],
            [{"type": "vcs", "url": "https://github.com/clawosiris/rust-gvm"}],
        )
        self.assertNotIn("compositions", transformed)

    def test_transform_declares_complete_generated_dependency_graph(self) -> None:
        document = json.loads(FIXTURE.read_text())

        transformed = transform_sbom(
            document,
            workspace_supplier="clawosiris",
            declare_dependency_complete=True,
        )

        self.assertEqual(
            transformed["compositions"],
            [
                {
                    "aggregate": "complete",
                    "dependencies": [
                        "path+file:///tmp/rust-gvm-sbom-improve/crates/gvm-client#0.1.0",
                        "path+file:///tmp/rust-gvm-sbom-improve/crates/gvm-connection#0.1.0",
                    ],
                }
            ],
        )

    def test_completeness_merges_with_an_existing_scoped_declaration(self) -> None:
        document = {
            "dependencies": [{"ref": "component-a", "dependsOn": []}],
            "compositions": [
                None,
                {"aggregate": "incomplete"},
                {"aggregate": "complete", "dependencies": ["component-existing"]},
            ],
        }

        ensure_dependency_completeness(document)

        self.assertEqual(
            document["compositions"][2]["dependencies"],
            ["component-existing", "component-a"],
        )

    def test_completeness_ignores_missing_or_unusable_dependency_graphs(self) -> None:
        documents = [
            {},
            {"dependencies": [None, {"ref": "", "dependsOn": []}]},
        ]

        for document in documents:
            with self.subTest(document=document):
                ensure_dependency_completeness(document)
                self.assertNotIn("compositions", document)

    def test_transform_preserves_valid_identity_and_skips_invalid_components(self) -> None:
        document = json.loads(FIXTURE.read_text())
        document["metadata"]["authors"] = [{"name": "Existing Author"}]
        document["metadata"]["supplier"] = {"name": "Existing Supplier"}
        document["components"].append(None)

        transformed = transform_sbom(document, workspace_supplier="clawosiris")

        self.assertEqual(
            transformed["metadata"]["authors"], [{"name": "Existing Author"}]
        )
        self.assertEqual(
            transformed["metadata"]["supplier"], {"name": "Existing Supplier"}
        )

    def test_script_overwrites_input_file(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="sbom-postprocess-"))
        self.addCleanup(shutil.rmtree, temp_dir)

        sbom_path = temp_dir / "input.cdx.json"
        sbom_path.write_text(FIXTURE.read_text())

        exit_code = main(
            [
                "--cargo-toml",
                str(ROOT / "Cargo.toml"),
                "--declare-dependency-complete",
                str(sbom_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        transformed = json.loads(sbom_path.read_text())
        self.assertEqual(transformed["metadata"]["licenses"][0]["license"]["id"], "CC0-1.0")
        self.assertEqual(transformed["compositions"][0]["aggregate"], "complete")


if __name__ == "__main__":
    unittest.main()
