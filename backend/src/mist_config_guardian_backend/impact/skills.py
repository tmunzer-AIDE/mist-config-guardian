"""Application-owned domain skills: allowlisted files and content-verified prompts."""

from hashlib import sha256
from importlib.resources import files

from pydantic import Field

from mist_config_guardian_backend.impact.contracts import Contract, WlanRemovalPlan

MAX_SKILL_BYTES = 1200


class SkillReference(Contract):
    id: str = Field(max_length=64)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class DomainSkill(SkillReference):
    instructions: str = Field(max_length=MAX_SKILL_BYTES)


_MANIFEST = {
    "port-availability.v1": (
        "port-availability.md",
        "cf0fccadd09947865f4c27a301b83b9ef691f593cf463a13b3aa157397c30ad0",
    ),
    "switch-poe.v1": ("switch-poe.md", "90edb5ddbeb3daf3a1ed1323b99e8ee50d7060c8a5ce5005c0fb37860ea2ebbd"),
    "wlan-authentication.v1": (
        "wlan-authentication.md",
        "4be0710f4a0e7c56c75881dcdcb58b0a4097b5c1c419fa2e3d71d05e703ad18b",
    ),
    "wlan-lifecycle.v1": ("wlan-lifecycle.md", "3bd278d732ec5795e1b2a3434934533590c4a366d2ce9f1e62b3de5b68dd4802"),
}


def selected_skills(plan: WlanRemovalPlan) -> tuple[DomainSkill, ...]:
    selected = set()
    if any(t.change_kind in {"removed", "disabled"} for t in plan.targets):
        selected.add("wlan-lifecycle.v1")
    if any(t.auth_changed for t in plan.targets):
        selected.add("wlan-authentication.v1")
    selected.update(domain for target in plan.port_targets for domain in target.domains)
    result = []
    for identity in sorted(selected):
        filename, expected = _MANIFEST[identity]
        raw = files("mist_config_guardian_backend.impact").joinpath("skill_assets", filename).read_bytes()
        if len(raw) > MAX_SKILL_BYTES or sha256(raw).hexdigest() != expected:
            msg = "Domain skill asset failed integrity validation"
            raise ValueError(msg)
        result.append(DomainSkill(id=identity, content_hash=expected, instructions=raw.decode()))
    return tuple(result)
