import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.sbom_postprocess import (
    ensure_build_lifecycle,
    ensure_dependency_completeness,
    ensure_metadata_license,
    infer_supplier,
    iter_components,
    load_workspace_supplier,
    looks_first_party,
    main,
    normalize_spec_version,
    transform_sbom,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sbom" / "minimal.cdx.json"


class SbomPostprocessTests(unittest.TestCase):
    def test_workspace_supplier_and_spec_version_fallbacks(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="sbom-workspace-"))
        self.addCleanup(shutil.rmtree, temp_dir)
        cargo_toml = temp_dir / "Cargo.toml"
        cargo_toml.write_text(
            '[workspace]\n[workspace.package]\nrepository = "https://example.com/repo"\n'
        )

        self.assertEqual(load_workspace_supplier(temp_dir / "missing.toml"), "clawosiris")
        self.assertEqual(load_workspace_supplier(cargo_toml), "clawosiris")
        self.assertEqual(normalize_spec_version(None), "1.5")
        self.assertEqual(normalize_spec_version("1.6"), "1.6")

    def test_metadata_license_and_lifecycle_preserve_or_append(self) -> None:
        existing = {
            "licenses": [None, {}, {"license": {"id": "CC0-1.0"}}],
            "lifecycles": [None, {"phase": "build"}],
        }
        ensure_metadata_license(existing)
        ensure_build_lifecycle(existing)
        self.assertEqual(len(existing["licenses"]), 3)
        self.assertEqual(len(existing["lifecycles"]), 2)

        missing = {
            "licenses": [None, {}, {"license": {"id": "MIT"}}],
            "lifecycles": [None, {"phase": "runtime"}],
        }
        ensure_metadata_license(missing)
        ensure_build_lifecycle(missing)
        self.assertEqual(missing["licenses"][-1], {"license": {"id": "CC0-1.0"}})
        self.assertEqual(missing["lifecycles"][-1], {"phase": "build"})

    def test_first_party_and_supplier_fallback_paths(self) -> None:
        repository_url = "https://github.com/clawosiris/rust-gvm"
        self.assertTrue(
            looks_first_party(
                {
                    "externalReferences": [
                        None,
                        {"type": "vcs", "url": repository_url},
                    ]
                },
                repository_url,
            )
        )
        self.assertFalse(
            looks_first_party(
                {"externalReferences": [{"type": "website", "url": repository_url}]},
                repository_url,
            )
        )
        self.assertIsNone(
            infer_supplier(
                {"supplier": {"name": "existing"}}, "clawosiris", repository_url
            )
        )
        self.assertIsNone(
            infer_supplier({"purl": "pkg:generic/example"}, "clawosiris", repository_url)
        )

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

    def test_completeness_adds_scope_when_existing_complete_has_no_dependencies(self) -> None:
        document = {
            "dependencies": [{"ref": "component-a", "dependsOn": []}],
            "compositions": [{"aggregate": "complete", "assemblies": ["component-a"]}],
        }

        ensure_dependency_completeness(document)

        self.assertEqual(
            document["compositions"][1],
            {"aggregate": "complete", "dependencies": ["component-a"]},
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

    def test_transform_supports_missing_primary_component_and_non_vcs_references(self) -> None:
        without_primary = {
            "specVersion": "1.6",
            "metadata": {},
            "components": [{"name": "generic", "purl": "pkg:generic/example"}],
        }
        self.assertEqual(
            iter_components(without_primary),
            [{"name": "generic", "purl": "pkg:generic/example"}],
        )
        transformed = transform_sbom(without_primary, workspace_supplier="clawosiris")
        self.assertNotIn("supplier", transformed["components"][0])

        invalid_primary_metadata = {
            "metadata": {
                "component": {
                    "name": "generic",
                    "licenses": "invalid",
                    "supplier": {"name": "existing"},
                    "externalReferences": [None, {"type": "website"}],
                }
            }
        }
        transformed = transform_sbom(
            invalid_primary_metadata, workspace_supplier="clawosiris"
        )
        self.assertEqual(
            transformed["metadata"]["component"]["supplier"],
            {"name": "existing"},
        )

    def test_transform_rejects_non_object_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata must be a JSON object"):
            transform_sbom({"metadata": []}, workspace_supplier="clawosiris")

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
