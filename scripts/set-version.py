#!/usr/bin/env python3
"""Synchronize application and deployment versions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
ROOT = Path(__file__).resolve().parent.parent


def replace(
    path: str,
    pattern: str,
    replacement: str,
    *,
    expected: int = 1,
    check: bool = False,
) -> None:
    """Replace an expected number of version declarations in one file."""
    target = ROOT / path
    content = target.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, content, flags=re.MULTILINE)
    if count != expected:
        message = f"{path}: expected {expected} version declaration(s), found {count}"
        raise RuntimeError(message)
    if check and updated != content:
        message = f"{path}: version is not synchronized"
        raise RuntimeError(message)
    if check:
        return
    target.write_text(updated, encoding="utf-8")


def main() -> None:
    """Update version declarations not managed by uv or npm."""
    check = len(sys.argv) == 3 and sys.argv[1] == "--check"
    if (len(sys.argv) not in {2, 3}) or (len(sys.argv) == 3 and not check):
        raise SystemExit("usage: scripts/set-version.py [--check] <major.minor.patch>")
    version = sys.argv[-1]
    if SEMVER.fullmatch(version) is None:
        raise SystemExit("version must use major.minor.patch format")

    replace(".env.example", r"^APP_VERSION=.*$", f"APP_VERSION={version}", check=check)
    replace(
        "backend/src/mist_config_guardian_backend/__init__.py",
        r'^__version__ = ".*"$',
        f'__version__ = "{version}"',
        check=check,
    )
    replace(
        "backend/src/mist_config_guardian_backend/config.py",
        r'^    app_version: str = ".*"$',
        f'    app_version: str = "{version}"',
        check=check,
    )
    replace(
        "helm/mist-config-guardian/Chart.yaml",
        r"^version: .*$",
        f"version: {version}",
        check=check,
    )
    replace(
        "helm/mist-config-guardian/Chart.yaml",
        r'^appVersion: ".*"$',
        f'appVersion: "{version}"',
        check=check,
    )
    replace(
        "helm/mist-config-guardian/values.yaml",
        r'^  tag: ".*"$',
        f'  tag: "{version}"',
        expected=2,
        check=check,
    )
    replace(
        "helm/mist-config-guardian/questions.yaml",
        r'^    default: "\d+\.\d+\.\d+"$',
        f'    default: "{version}"',
        expected=2,
        check=check,
    )


if __name__ == "__main__":
    main()
