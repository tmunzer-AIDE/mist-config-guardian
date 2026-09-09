#!/usr/bin/env python3
"""Export the OpenAPI document, or verify the committed copy is current.

The committed document at ``docs/openapi.json`` is the API contract the browser
application and any integration are written against. Keeping it in the
repository makes a contract change visible in review rather than only at
runtime, so ``--check`` runs in ``make check`` and fails when it drifts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_SRC = ROOT / "backend" / "src"
OUTPUT = ROOT / "docs" / "openapi.json"


def build_document() -> dict[str, object]:
    """Return the OpenAPI document for a deterministic, database-free app."""
    sys.path.insert(0, str(BACKEND_SRC))
    from mist_config_guardian_backend.config import Settings  # noqa: PLC0415
    from mist_config_guardian_backend.main import create_app  # noqa: PLC0415

    settings = Settings(environment="test", database_enabled=False)
    return create_app(settings).openapi()


def serialize(document: dict[str, object]) -> str:
    """Render the document stably so an unrelated edit produces no diff."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    """Write or verify the committed OpenAPI document."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the committed document differs from the current API.",
    )
    arguments = parser.parse_args()

    rendered = serialize(build_document())

    if arguments.check:
        if not OUTPUT.exists():
            print(f"{OUTPUT.relative_to(ROOT)} is missing; run: make openapi", file=sys.stderr)
            return 1
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            print(
                f"{OUTPUT.relative_to(ROOT)} is out of date; run: make openapi",
                file=sys.stderr,
            )
            return 1
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    paths = json.loads(rendered)["paths"]
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(paths)} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
