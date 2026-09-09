"""Contract export ignores local deployment version overrides."""

import runpy
from pathlib import Path

from mist_config_guardian_backend import __version__


def test_export_version_is_independent_of_environment_and_working_directory(monkeypatch, tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts" / "export-openapi.py"
    namespace = runpy.run_path(str(script))
    (tmp_path / ".env").write_text("APP_VERSION=0.1.0\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APP_VERSION", "9.9.9")
    document = namespace["build_document"]()
    assert document["info"]["version"] == __version__
