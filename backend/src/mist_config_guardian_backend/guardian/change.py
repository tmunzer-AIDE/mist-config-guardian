"""Guardian's change model: which paths of which attributes an audit changed, and a bounded, masked view of them.

An atom ``A<n>`` is one logical object version's top-level functional attribute, with every path the diff walker
found below it. Atoms carry paths only. Masked before/after values leave this module only through
:func:`change_view`, the one bounded view the prompt and the report share.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from mist_config_guardian_backend.guardian.contracts import (
    MAX_IDENTIFIER_CHARS,
    MAX_TEXT_CHARS,
    AtomId,
    ChangeAtom,
    ConfigPath,
    Contract,
    DeviceMac,
    Identifier,
)
from mist_config_guardian_backend.guardian.evidence import CHANGE_VIEW_BUDGET, Bounded, bounded
from mist_config_guardian_backend.schemas.diff import DiffChangeKind
from mist_config_guardian_backend.services.diff import changed_entries, changed_paths
from mist_config_guardian_backend.snapshots.canonical import changed_top_level_fields
from mist_config_guardian_backend.snapshots.registry import DEFAULT_IGNORED_FIELDS, get_definition

CHANGE_VIEW_CHANGES_PER_ATOM = 3
MAX_VIEW_PATH_CHARS = 200

Scope = Literal["org", "site"]
ChangeKind = Literal["added", "modified", "removed"]
Name = Annotated[str, StringConstraints(max_length=MAX_IDENTIFIER_CHARS)]
DisplayValue = Annotated[str, StringConstraints(max_length=MAX_TEXT_CHARS)]

_KINDS: dict[DiffChangeKind, ChangeKind] = {
    DiffChangeKind.ADDED: "added",
    DiffChangeKind.MODIFIED: "modified",
    DiffChangeKind.REMOVED: "removed",
}


def covers(prefix: tuple[str, ...], path: tuple[str, ...]) -> bool:
    """Whether ``prefix`` names ``path`` or an ancestor of it, comparing whole segments: ``ports.1`` never covers
    ``ports.10``."""
    return len(prefix) <= len(path) and path[: len(prefix)] == prefix


@dataclass(frozen=True, slots=True)
class ObjectChange:
    """One changed logical object version as stored: its identity and its protected configuration on each side.

    ``before`` is empty for a created object and ``after`` for a deleted one. Secrets stay in their stored,
    encrypted form; the diff walker compares their fingerprints and masks them. ``device_mac`` is set only for a
    device object, whose one applicable target is that device.
    """

    logical_object_id: str
    scope: Scope
    object_type: str
    name: str
    version: int
    before: Mapping[str, object]
    after: Mapping[str, object]
    site_id: str | None = None
    device_mac: str | None = None


class ChangedObject(Contract):
    logical_object_id: Identifier
    scope: Scope
    object_type: Identifier
    name: Name = ""
    version: int = Field(ge=1)
    site_id: Identifier | None = None
    device_mac: DeviceMac | None = None


class PathChange(Contract):
    """One changed location for display: the diff's path text and its masked, shortened values."""

    path: Annotated[str, StringConstraints(min_length=1, max_length=MAX_VIEW_PATH_CHARS)]
    kind: ChangeKind
    before: DisplayValue | None = None
    after: DisplayValue | None = None


class AtomView(Contract):
    id: AtomId
    object_type: Identifier
    name: Name = ""
    site_id: Identifier | None = None
    device_mac: DeviceMac | None = None
    attribute: Identifier
    path_count: int = Field(ge=1)
    paths_complete: bool
    changes: tuple[PathChange, ...] = Field(default=(), max_length=CHANGE_VIEW_CHANGES_PER_ATOM)


class ChangeSet(Contract):
    """The atoms of one audit, the objects they belong to, and the first few masked changes of each atom."""

    objects: tuple[ChangedObject, ...] = ()
    atoms: tuple[ChangeAtom, ...] = ()
    masked: dict[AtomId, tuple[PathChange, ...]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def atoms_belong_to_objects(self) -> "ChangeSet":
        objects = {(item.logical_object_id, item.version) for item in self.objects}
        if any((atom.logical_object_id, atom.version) not in objects for atom in self.atoms):
            msg = "Every atom belongs to an object of the change set"
            raise ValueError(msg)
        if not set(self.masked) <= {atom.id for atom in self.atoms}:
            msg = "Masked changes belong to atoms of the change set"
            raise ValueError(msg)
        return self

    def object_of(self, atom: ChangeAtom) -> ChangedObject:
        for item in self.objects:
            if (item.logical_object_id, item.version) == (atom.logical_object_id, atom.version):
                return item
        raise KeyError(atom.id)


def build_change_set(changes: Iterable[ObjectChange]) -> ChangeSet:
    """Build atoms with stable ids: objects in (logical object, version) order, then attributes by name.

    Metadata fields never form atoms or paths: each object is compared under its registry definition's ignored
    fields, the same set its digest ignores. When the walker's cap truncates an object, every atom of that object is
    incomplete, and a changed attribute the walker never reached still gets an atom whose only path is the attribute.
    """
    ordered = sorted(changes, key=lambda change: (change.logical_object_id, change.version))
    identities = [(change.logical_object_id, change.version) for change in ordered]
    if len(set(identities)) != len(identities):
        msg = "Each logical object version appears once in a change set"
        raise ValueError(msg)
    objects: list[ChangedObject] = []
    atoms: list[ChangeAtom] = []
    masked: dict[str, tuple[PathChange, ...]] = {}
    for change in ordered:
        objects.append(
            ChangedObject(
                logical_object_id=change.logical_object_id,
                scope=change.scope,
                object_type=change.object_type,
                name=change.name[:MAX_IDENTIFIER_CHARS],
                version=change.version,
                site_id=change.site_id,
                device_mac=change.device_mac,
            )
        )
        ignored = _ignored_fields(change)
        found = changed_paths(change.before, change.after, ignored)
        paths: defaultdict[str, set[tuple[str, ...]]] = defaultdict(set)
        for path in found.paths:
            nameable = _nameable(path)
            paths[nameable[0]].add(nameable)
        if not found.complete:
            for attribute in changed_top_level_fields(change.before, change.after, ignored_fields=ignored):
                paths.setdefault(attribute, {_nameable((attribute,))})
        samples = _masked_samples(change, ignored)
        for attribute in sorted(paths):
            atom = ChangeAtom(
                id=f"A{len(atoms) + 1}",
                logical_object_id=change.logical_object_id,
                version=change.version,
                attribute=attribute,
                paths=tuple(sorted(paths[attribute])),
                paths_complete=found.complete,
            )
            atoms.append(atom)
            masked[atom.id] = samples.get(attribute, ())
    return ChangeSet(objects=tuple(objects), atoms=tuple(atoms), masked=masked)


def change_view(change: ChangeSet, *, budget: int = CHANGE_VIEW_BUDGET) -> Bounded[AtomView]:
    """Atoms in id order with their first masked changes, within ``budget``; omitted atoms counted by object type."""
    views = []
    for atom in change.atoms:
        changed = change.object_of(atom)
        views.append(
            AtomView(
                id=atom.id,
                object_type=changed.object_type,
                name=changed.name,
                site_id=changed.site_id,
                device_mac=changed.device_mac,
                attribute=atom.attribute,
                path_count=len(atom.paths),
                paths_complete=atom.paths_complete,
                changes=change.masked.get(atom.id, ()),
            )
        )
    return bounded(
        views,
        budget=budget,
        priority=lambda view: int(view.id[1:]),
        category=lambda view: view.object_type,
        build=lambda items, omitted: Bounded[AtomView](items=items, omitted=omitted),
    )


def _ignored_fields(change: ObjectChange) -> frozenset[str]:
    definition = get_definition(change.scope, change.object_type)
    return DEFAULT_IGNORED_FIELDS if definition is None else definition.ignored_fields


def _nameable(path: tuple[str, ...]) -> ConfigPath:
    """The path as far as each segment can be named. A parent stands for a child whose key is empty or too long."""
    for index, segment in enumerate(path):
        if not 1 <= len(segment) <= MAX_IDENTIFIER_CHARS:
            if index == 0:
                msg = f"A changed top-level attribute is empty or longer than {MAX_IDENTIFIER_CHARS} characters"
                raise ValueError(msg)
            return path[:index]
    return path


def _masked_samples(change: ObjectChange, ignored: frozenset[str]) -> dict[str, tuple[PathChange, ...]]:
    samples: defaultdict[str, list[PathChange]] = defaultdict(list)
    for path, entry in sorted(changed_entries(change.before, change.after, ignored), key=lambda located: located[0]):
        attribute = samples[path[0]]
        if len(attribute) < CHANGE_VIEW_CHANGES_PER_ATOM:
            attribute.append(
                PathChange(
                    path=_shorten(entry.field),
                    kind=_KINDS[entry.kind],
                    before=entry.before,
                    after=entry.after,
                )
            )
    return {name: tuple(rows) for name, rows in samples.items()}


def _shorten(text: str) -> str:
    return text if len(text) <= MAX_VIEW_PATH_CHARS else f"{text[: MAX_VIEW_PATH_CHARS - 1]}…"
