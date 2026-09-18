#!/usr/bin/env python3
"""Drop the five collections the removed impact engine owned.

Guardian replaced that engine. Nothing in the application reads or writes these collections any more, so they
sit in the database holding investigations, revisions, model-request artifacts, adjudications and neighbour
bindings that no page can show. This removes them.

It is operator tooling, not a migration: no startup path, task or schedule runs it, and it drops nothing until
``--apply`` is given. It names only the five collections below -- never a Guardian or application collection --
reports every one of them with its document count whether or not it is present, and can be run again safely:
a collection already gone is reported as absent and left alone. Every operation it sends is bounded in time, so
an unresponsive server ends the command instead of hanging it; re-running finishes what a bound cut short.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

import pymongo
from pymongo import AsyncMongoClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))

from mist_config_guardian_backend.config import get_settings  # noqa: E402

# One deadline for the whole cleanup. ``serverSelectionTimeoutMS`` bounds picking a server and nothing after it,
# so a server selected and then unresponsive would hang the listing, a count or a drop forever. It is applied
# around the cleanup rather than to the client, so connecting keeps its own short bound. A run this cuts short is
# safe to repeat: every collection already dropped is reported as absent the next time.
OPERATION_TIMEOUT_SECONDS = 60.0

# The exact collections of the removed engine, in a stable order so two runs read the same way.
LEGACY_COLLECTIONS = (
    "impact_adjudications",
    "impact_investigations",
    "impact_model_request_artifacts",
    "investigation_revisions",
    "neighbor_bindings",
)


async def _documents(database: Any, name: str) -> int | None:
    """How many documents the collection holds, or ``None`` when that cannot be read."""
    try:
        return await database[name].estimated_document_count()
    except Exception:  # noqa: BLE001 - an unreadable count must not stop the drop it only annotates.
        return None


async def drop_legacy_collections(database: Any, *, apply: bool) -> list[str]:
    """Report every legacy collection, drop the present ones when asked, and return what was dropped."""
    existing = set(await database.list_collection_names())
    present = [name for name in LEGACY_COLLECTIONS if name in existing]
    for name in LEGACY_COLLECTIONS:
        if name not in present:
            print(f"  {name:<32} absent")
            continue
        documents = await _documents(database, name)
        count = "unknown" if documents is None else f"{documents}"
        print(f"  {name:<32} {count} documents")

    verb = "Dropping" if apply else "Would drop"
    print(f"{verb} {len(present)} of {len(LEGACY_COLLECTIONS)} legacy collections.")
    if not apply:
        print("Re-run with --apply to drop them.")
        return []
    dropped = []
    # Each drop is announced as it happens, so a run that dies partway through -- a revoked permission, a
    # stepdown -- still leaves the operator a record of exactly what is already gone.
    for name in present:
        await database.drop_collection(name)
        dropped.append(name)
        print(f"  dropped {name}")
    print(f"Dropped {len(dropped)} collections: {', '.join(dropped) if dropped else 'none'}.")
    return dropped


async def run(*, apply: bool) -> int:
    """Connect with the application's configured MongoDB settings and run the cleanup."""
    settings = get_settings()
    # A raw client on purpose: the document models are not registered any more, and initializing them here would
    # create the application's own collections and indexes as a side effect of a cleanup command.
    client = AsyncMongoClient(
        settings.mongodb_url,
        serverSelectionTimeoutMS=int(settings.mongodb_connect_timeout_seconds * 1000),
        tz_aware=True,
    )
    try:
        await client.admin.command("ping")
        print(f"Database {settings.mongodb_db_name}:")
        with pymongo.timeout(OPERATION_TIMEOUT_SECONDS):
            await drop_legacy_collections(client[settings.mongodb_db_name], apply=apply)
    finally:
        await client.close()
    return 0


def main() -> int:
    """Parse arguments and run the cleanup."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="drop the reported collections instead of only listing them",
    )
    return asyncio.run(run(apply=parser.parse_args().apply))


if __name__ == "__main__":
    raise SystemExit(main())
