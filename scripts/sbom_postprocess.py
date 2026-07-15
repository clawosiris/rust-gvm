#!/usr/bin/env python3
"""Deterministically improve CycloneDX SBOM metadata for CI scoring."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


CC0_LICENSE = {"license": {"id": "CC0-1.0"}}
BUILD_LIFECYCLE = {"phase": "build"}
WORKSPACE_SUPPLIER_FALLBACK = "clawosiris"
REGISTRY_SUPPLIER = "crates.io"


def load_workspace_supplier(cargo_toml_path: Path) -> str:
    try:
        workspace = tomllib.loads(cargo_toml_path.read_text()).get("workspace", {})
    except FileNotFoundError:
        return WORKSPACE_SUPPLIER_FALLBACK

    repository = workspace.get("package", {}).get("repository", "")
    match = re.search(r"github\.com/([^/]+)/", repository)
    if match:
        return match.group(1)
    return WORKSPACE_SUPPLIER_FALLBACK


def normalize_spec_version(value: Any) -> str:
    try:
        major, minor = [int(part) for part in str(value).split(".")[:2]]
    except (TypeError, ValueError):
        return "1.5"

    if (major, minor) < (1, 5):
        return "1.5"
    return f"{major}.{minor}"


def ensure_metadata_license(metadata: dict[str, Any]) -> None:
    licenses = metadata.get("licenses")
    if not isinstance(licenses, list):
        metadata["licenses"] = [CC0_LICENSE]
        return

    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        license_data = entry.get("license")
        if isinstance(license_data, dict) and license_data.get("id") == "CC0-1.0":
            return

    licenses.append(CC0_LICENSE)


def ensure_build_lifecycle(metadata: dict[str, Any]) -> None:
    lifecycles = metadata.get("lifecycles")
    if not isinstance(lifecycles, list):
        metadata["lifecycles"] = [BUILD_LIFECYCLE]
        return

    for entry in lifecycles:
        if isinstance(entry, dict) and entry.get("phase") == "build":
            return

    lifecycles.append(BUILD_LIFECYCLE)


def ensure_metadata_identity(metadata: dict[str, Any], workspace_supplier: str) -> None:
    authors = metadata.get("authors")
    if not isinstance(authors, list) or not any(
        isinstance(author, dict) and author.get("name") for author in authors
    ):
        metadata["authors"] = [{"name": workspace_supplier}]

    supplier = metadata.get("supplier")
    if not isinstance(supplier, dict) or not supplier.get("name"):
        metadata["supplier"] = {"name": workspace_supplier}


def looks_first_party(component: dict[str, Any], repository_url: str) -> bool:
    bom_ref = str(component.get("bom-ref", ""))
    purl = str(component.get("purl", ""))
    if bom_ref.startswith("path+file://") or "download_url=file://" in purl:
        return True

    for ref in component.get("externalReferences", []):
        if not isinstance(ref, dict):
            continue
        if ref.get("type") == "vcs" and ref.get("url") == repository_url:
            return True

    return False


def infer_supplier(
    component: dict[str, Any],
    workspace_supplier: str,
    repository_url: str,
) -> dict[str, str] | None:
    if component.get("supplier"):
        return None

    if looks_first_party(component, repository_url):
        return {"name": workspace_supplier}

    purl = str(component.get("purl", ""))
    if purl.startswith("pkg:cargo/"):
        return {"name": REGISTRY_SUPPLIER}

    return None


def iter_components(document: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []

    def append_components(values: Any) -> None:
        if not isinstance(values, list):
            return
        for component in values:
            if not isinstance(component, dict):
                continue
            components.append(component)
            append_components(component.get("components"))

    metadata = document.get("metadata", {})
    metadata_component = metadata.get("component")
    if isinstance(metadata_component, dict):
        components.append(metadata_component)
        append_components(metadata_component.get("components"))

    append_components(document.get("components"))

    return components


def ensure_first_party_metadata(
    component: dict[str, Any],
    repository_url: str,
    workspace_licenses: list[Any],
) -> None:
    if not looks_first_party(component, repository_url):
        return

    if not component.get("licenses") and workspace_licenses:
        component["licenses"] = copy.deepcopy(workspace_licenses)

    references = component.get("externalReferences")
    if not isinstance(references, list):
        references = []
        component["externalReferences"] = references
    if repository_url and not any(
        isinstance(reference, dict)
        and reference.get("type") == "vcs"
        and reference.get("url") == repository_url
        for reference in references
    ):
        references.append({"type": "vcs", "url": repository_url})


def ensure_dependency_completeness(document: dict[str, Any]) -> None:
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        return

    dependency_refs = list(
        dict.fromkeys(
            str(dependency.get("ref"))
            for dependency in dependencies
            if isinstance(dependency, dict)
            and dependency.get("ref")
            and isinstance(dependency.get("dependsOn"), list)
        )
    )
    if not dependency_refs:
        return

    compositions = document.get("compositions")
    if not isinstance(compositions, list):
        compositions = []
        document["compositions"] = compositions

    for composition in compositions:
        if not isinstance(composition, dict) or composition.get("aggregate") != "complete":
            continue
        declared = composition.get("dependencies")
        if isinstance(declared, list):
            composition["dependencies"] = list(
                dict.fromkeys([*(str(item) for item in declared), *dependency_refs])
            )
            return

    compositions.append({"aggregate": "complete", "dependencies": dependency_refs})


def transform_sbom(
    document: dict[str, Any],
    workspace_supplier: str,
    *,
    declare_dependency_complete: bool = False,
) -> dict[str, Any]:
    document["specVersion"] = normalize_spec_version(document.get("specVersion"))

    metadata = document.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("SBOM metadata must be a JSON object")

    ensure_metadata_license(metadata)
    ensure_build_lifecycle(metadata)
    ensure_metadata_identity(metadata, workspace_supplier)

    repository_url = ""
    workspace_licenses: list[Any] = []
    metadata_component = metadata.get("component")
    if isinstance(metadata_component, dict):
        licenses = metadata_component.get("licenses")
        if isinstance(licenses, list):
            workspace_licenses = licenses
        for ref in metadata_component.get("externalReferences", []):
            if not isinstance(ref, dict):
                continue
            if ref.get("type") == "vcs":
                repository_url = str(ref.get("url", ""))
                break

    for component in iter_components(document):
        supplier = infer_supplier(component, workspace_supplier, repository_url)
        if supplier is not None:
            component["supplier"] = supplier
        ensure_first_party_metadata(component, repository_url, workspace_licenses)

    if declare_dependency_complete:
        ensure_dependency_completeness(document)

    return document


def process_file(
    path: Path,
    workspace_supplier: str,
    *,
    declare_dependency_complete: bool = False,
) -> None:
    document = json.loads(path.read_text())
    transformed = transform_sbom(
        document,
        workspace_supplier,
        declare_dependency_complete=declare_dependency_complete,
    )
    path.write_text(json.dumps(transformed, indent=2) + "\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", nargs="+", type=Path, help="CycloneDX JSON files to rewrite")
    parser.add_argument(
        "--cargo-toml",
        type=Path,
        default=Path("Cargo.toml"),
        help="Workspace Cargo.toml used to infer the first-party supplier name",
    )
    parser.add_argument(
        "--declare-dependency-complete",
        action="store_true",
        help=(
            "declare the dependency relationships complete; use only for SBOMs "
            "generated from the complete cargo-cyclonedx dependency graph"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace_supplier = load_workspace_supplier(args.cargo_toml)
    for sbom_path in args.sbom:
        process_file(
            sbom_path,
            workspace_supplier,
            declare_dependency_complete=args.declare_dependency_complete,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
