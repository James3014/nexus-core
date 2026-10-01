from __future__ import annotations

import importlib.util
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "distribution" / "nexus-verify-plugin"
MANIFEST = PACKAGE / ".codex-plugin" / "plugin.json"
MCP = PACKAGE / ".mcp.json"
ICON = PACKAGE / "assets" / "icon.svg"
PACKAGER = ROOT / "scripts" / "package_nexus_verify_plugin.py"


def _load_packager():
    spec = importlib.util.spec_from_file_location("nexus_verify_plugin_packager", PACKAGER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_plugin_manifest_is_submission_shaped():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    interface = manifest["interface"]
    review = manifest["extensions"]["com.openai"]["review"]
    publication = manifest["extensions"]["com.openai"]["publication"]

    assert manifest["name"] == "nexus-verify"
    assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["version"])
    assert len(interface["displayName"]) <= 30
    assert len(interface["shortDescription"]) <= 30
    assert len(interface["longDescription"]) <= 4000
    assert len(interface["developerName"]) <= 80
    assert interface["category"] == "Developer Tools"
    assert interface["websiteURL"] == "https://verify.snowskill.app/"
    assert interface["supportURL"] == "https://verify.snowskill.app/support/"
    assert interface["privacyPolicyURL"] == "https://verify.snowskill.app/privacy/"
    assert interface["termsOfServiceURL"] == "https://verify.snowskill.app/terms/"
    assert interface["composerIcon"] == "./assets/icon.svg"
    assert interface["logo"] == "./assets/icon.svg"
    assert "screenshots" not in interface
    assert len(interface["defaultPrompt"]) == 3
    assert all(len(prompt) <= 128 for prompt in interface["defaultPrompt"])
    assert len(review["test_cases"]["positive"]) == 5
    assert len(review["test_cases"]["negative"]) == 3
    assert all(
        case["tools_triggered"] == "verify_code_change_evidence"
        and case["expected_behavior"]
        for case in review["test_cases"]["positive"]
    )
    assert review["commerce"] is False
    assert publication["release_notes"]


def test_mcp_manifest_points_only_to_production_endpoint():
    config = json.loads(MCP.read_text(encoding="utf-8"))
    assert config == {
        "mcpServers": {
            "nexus-verify": {
                "url": "https://verify.snowskill.app/mcp",
            }
        }
    }


def test_icon_is_square_and_submission_eligible_svg():
    source = ICON.read_text(encoding="utf-8")
    assert '<svg ' in source
    assert 'width="128"' in source
    assert 'height="128"' in source
    assert 'viewBox="0 0 128 128"' in source


def test_packager_is_reproducible(tmp_path: Path):
    module = _load_packager()
    first = module.build(tmp_path / "first.zip")
    second = module.build(tmp_path / "second.zip")
    assert first.read_bytes() == second.read_bytes()

    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == [
            ".codex-plugin/plugin.json",
            ".mcp.json",
            "assets/icon.svg",
        ]
        stored = json.loads(archive.read(".codex-plugin/plugin.json"))
        assert stored["version"] == "0.1.1"
