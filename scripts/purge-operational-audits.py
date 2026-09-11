#!/usr/bin/env python3
"""Remove change groups stored before audits were filtered at ingestion.

Ingestion now stores only audits that changed configuration. Anything received
before that is still in the database -- accessed-org events, packet captures,
logins -- burying the real changes in the timeline. This removes them.

Reports what it would delete and exits without writing anything unless
``--apply`` is given.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))

from mist_config_guardian_backend.config import get_settings  # noqa: E402
from mist_config_guardian_backend.database import DatabaseManager  # noqa: E402
from mist_config_guardian_backend.models.organization import Organization  # noqa: E402
from mist_config_guardian_backend.models.webhook import AuditChangeGroup  # noqa: E402
from mist_config_guardian_backend.security.credentials import CredentialVault  # noqa: E402
from mist_config_guardian_backend.services.audit_cleanup import (  # noqa: E402
    audit_payloads,
    is_operational_noise,
    purge_group,
)


async def purge(*, apply: bool) -> int:
    """Report, and optionally delete, every change group that changed nothing."""
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    vault = CredentialVault(settings)
    try:
        organizations = {
            organization.id: organization.mist_org_id for organization in await Organization.find_all().to_list()
        }
        groups = await AuditChangeGroup.find_all().to_list()
        noise = []
        for group in groups:
            mist_org_id = organizations.get(group.organization_id)
            if mist_org_id is None:
                # Without the organization the payloads cannot be decrypted, and
                # a group judged on no evidence is not a group worth deleting.
                continue
            payloads = await audit_payloads(group, vault, mist_org_id=mist_org_id)
            if is_operational_noise(group, payloads):
                noise.append(group)

        for group in noise:
            print(f"  {group.occurred_at:%Y-%m-%d %H:%MZ}  {group.audit_id}  {group.message or '(no message)'}")
        verb = "Deleting" if apply else "Would delete"
        print(f"{verb} {len(noise)} of {len(groups)} change groups.")
        if not apply:
            print("Re-run with --apply to delete them.")
            return 0
        receipts = 0
        for group in noise:
            receipts += await purge_group(group)
        print(f"Deleted {len(noise)} change groups and {receipts} audit receipts.")
    finally:
        await database.close()
    return 0


def main() -> int:
    """Parse arguments and run the purge."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="delete the reported change groups instead of only listing them",
    )
    return asyncio.run(purge(apply=parser.parse_args().apply))


if __name__ == "__main__":
    raise SystemExit(main())
