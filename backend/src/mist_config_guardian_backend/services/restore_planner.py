"""Dependency-aware immutable restore planning."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
)
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
)
from mist_config_guardian_backend.snapshots.registry import get_definition


class RestorePlanningError(ValueError):
    """Raised when selected history cannot form a safe restore plan."""


@dataclass
class PlanningContext:
    """Mutable target set while dependencies are expanded."""

    organization_id: PydanticObjectId
    selected: dict[PydanticObjectId, ObjectVersion]
    logical_objects: dict[PydanticObjectId, LogicalObject]
    force_delete: set[PydanticObjectId]
    target_at: datetime
    mode: RestoreMode


class RestorePlanner:
    """Build reviewable plans without making Mist API writes."""

    async def create_plan(
        self,
        *,
        organization_id: PydanticObjectId,
        requested_by: PydanticObjectId,
        version_ids: list[PydanticObjectId],
        mode: RestoreMode,
        include_dependencies: bool,
    ) -> RestoreOperation:
        """Build and persist a dependency-ordered multi-object plan."""
        if not version_ids:
            msg = "At least one version is required"
            raise RestorePlanningError(msg)

        selected: dict[PydanticObjectId, ObjectVersion] = {}
        logical_objects: dict[PydanticObjectId, LogicalObject] = {}
        force_delete: set[PydanticObjectId] = set()
        for version_id in version_ids:
            version = await ObjectVersion.get(version_id)
            if version is None or version.organization_id != organization_id:
                msg = "One or more selected versions were not found"
                raise RestorePlanningError(msg)
            if version.logical_object_id in selected:
                msg = "Only one target version may be selected per object"
                raise RestorePlanningError(msg)
            logical = await LogicalObject.get(version.logical_object_id)
            if logical is None:
                msg = "A selected version has no logical object"
                raise RestorePlanningError(msg)
            selected[version.logical_object_id] = version
            logical_objects[version.logical_object_id] = logical

        target_at = min(version.observed_at for version in selected.values())
        if include_dependencies:
            await self._expand_dependencies(
                PlanningContext(
                    organization_id=organization_id,
                    selected=selected,
                    logical_objects=logical_objects,
                    force_delete=force_delete,
                    target_at=target_at,
                    mode=mode,
                )
            )

        actions = await self._build_actions(
            organization_id,
            selected,
            logical_objects,
            force_delete,
        )
        self._add_containment_delete_dependencies(actions)
        actions = order_restore_actions(actions)
        preflight_errors = self._validate_capabilities(actions)
        operation = RestoreOperation(
            organization_id=organization_id,
            requested_by=requested_by,
            mode=mode,
            include_dependencies=include_dependencies,
            target_at=target_at,
            actions=actions,
            warnings=[] if actions else ["Selected versions already match the recorded current state"],
            preflight_errors=preflight_errors,
        )
        await operation.insert()
        return operation

    @staticmethod
    def _validate_capabilities(actions: list[RestoreAction]) -> list[str]:
        errors: list[str] = []
        for action in actions:
            definition = get_definition(action.scope, action.object_type)
            if definition is None or not definition.supports_restore_action(action.action):
                errors.append(
                    f"{action.object_name}: {action.action} is not supported for {action.scope}:{action.object_type}"
                )
        return errors

    async def _expand_dependencies(self, context: PlanningContext) -> None:
        pending = deque(context.selected.values())
        while pending:
            version = pending.popleft()
            logical = context.logical_objects[version.logical_object_id]
            related = await self._related_logical_objects(
                context.organization_id,
                logical,
                version,
            )
            for related_logical in related:
                if related_logical.id is None or related_logical.id in context.selected:
                    continue
                target_version = await self._version_at(
                    related_logical.id,
                    context.target_at,
                )
                if target_version is None:
                    if context.mode is RestoreMode.NON_DESTRUCTIVE:
                        continue
                    target_version = await self._latest_version(related_logical.id)
                    if target_version is None:
                        continue
                    context.force_delete.add(related_logical.id)
                context.selected[related_logical.id] = target_version
                context.logical_objects[related_logical.id] = related_logical
                pending.append(target_version)
            if logical.is_deleted and not version.is_deleted:
                reverse_dependents = await self._reverse_dependents(
                    context.organization_id,
                    logical,
                )
                for dependent, current_version in reverse_dependents:
                    if dependent.id is None or dependent.id in context.selected:
                        continue
                    context.selected[dependent.id] = current_version
                    context.logical_objects[dependent.id] = dependent
                    pending.append(current_version)

    async def _related_logical_objects(
        self,
        organization_id: PydanticObjectId,
        logical: LogicalObject,
        version: ObjectVersion,
    ) -> list[LogicalObject]:
        related: dict[PydanticObjectId, LogicalObject] = {}
        if logical.object_type == "data":
            candidates = await LogicalObject.find(LogicalObject.organization_id == organization_id).to_list()
            related.update({item.id: item for item in candidates if item.id is not None})
        elif logical.object_type == "sites":
            candidates = await LogicalObject.find(
                LogicalObject.organization_id == organization_id,
                LogicalObject.site_mist_id == logical.current_mist_id,
            ).to_list()
            related.update({item.id: item for item in candidates if item.id is not None})

        for reference in version.references:
            incarnation = await ObjectIncarnation.find_one(
                ObjectIncarnation.organization_id == organization_id,
                ObjectIncarnation.mist_object_id == reference.target_mist_id,
            )
            if incarnation is None:
                continue
            referenced = await LogicalObject.get(incarnation.logical_object_id)
            if referenced is not None and referenced.id is not None:
                related[referenced.id] = referenced
        return list(related.values())

    async def _reverse_dependents(
        self,
        organization_id: PydanticObjectId,
        logical: LogicalObject,
    ) -> list[tuple[LogicalObject, ObjectVersion]]:
        candidates = await ObjectVersion.find(
            ObjectVersion.organization_id == organization_id,
            {"references.target_mist_id": logical.current_mist_id},
        ).to_list()
        dependents: list[tuple[LogicalObject, ObjectVersion]] = []
        seen: set[PydanticObjectId] = set()
        for candidate in candidates:
            if candidate.logical_object_id in seen:
                continue
            current = await self._latest_version(candidate.logical_object_id)
            if current is None or current.id != candidate.id or current.is_deleted:
                continue
            dependent = await LogicalObject.get(candidate.logical_object_id)
            if dependent is None or dependent.id is None:
                continue
            seen.add(dependent.id)
            dependents.append((dependent, current))
        return dependents

    async def _build_actions(
        self,
        organization_id: PydanticObjectId,
        selected: dict[PydanticObjectId, ObjectVersion],
        logical_objects: dict[PydanticObjectId, LogicalObject],
        force_delete: set[PydanticObjectId],
    ) -> list[RestoreAction]:
        actions: list[RestoreAction] = []
        for logical_id, target in selected.items():
            logical = logical_objects[logical_id]
            latest = await self._latest_version(logical_id)
            if latest is None or target.id is None:
                continue
            action_type = self._action_type(
                logical,
                target,
                latest,
                force_delete=logical_id in force_delete,
            )
            if action_type is None:
                continue
            dependencies = await self._action_dependencies(
                organization_id,
                target,
                selected,
                logical_objects,
                action_type,
            )
            actions.append(
                RestoreAction(
                    logical_object_id=logical_id,
                    source_version_id=target.id,
                    order=0,
                    action=action_type,
                    scope=logical.scope,
                    object_type=logical.object_type,
                    object_name=logical.name,
                    current_mist_id=logical.current_mist_id,
                    site_mist_id=logical.site_mist_id,
                    protected_configuration=target.configuration,
                    expected_current_hash=(None if logical.is_deleted else latest.configuration_hash),
                    depends_on=dependencies,
                )
            )
        return actions

    @staticmethod
    def _add_containment_delete_dependencies(actions: list[RestoreAction]) -> None:
        delete_actions = {
            action.logical_object_id: action for action in actions if action.action is RestoreActionType.DELETE
        }
        for parent in delete_actions.values():
            if parent.object_type == "sites":
                children = [
                    action.logical_object_id
                    for action in delete_actions.values()
                    if action.site_mist_id == parent.current_mist_id
                ]
                parent.depends_on = sorted(set(parent.depends_on) | set(children), key=str)
            elif parent.object_type == "data":
                children = [
                    action.logical_object_id
                    for action in delete_actions.values()
                    if action.logical_object_id != parent.logical_object_id
                ]
                parent.depends_on = sorted(set(parent.depends_on) | set(children), key=str)

    async def _action_dependencies(
        self,
        organization_id: PydanticObjectId,
        target: ObjectVersion,
        selected: dict[PydanticObjectId, ObjectVersion],
        logical_objects: dict[PydanticObjectId, LogicalObject],
        action_type: RestoreActionType,
    ) -> list[PydanticObjectId]:
        dependencies: set[PydanticObjectId] = set()
        if action_type is not RestoreActionType.DELETE:
            for reference in target.references:
                incarnation = await ObjectIncarnation.find_one(
                    ObjectIncarnation.organization_id == organization_id,
                    ObjectIncarnation.mist_object_id == reference.target_mist_id,
                )
                if (
                    incarnation is not None
                    and incarnation.logical_object_id in selected
                    and logical_objects[incarnation.logical_object_id].is_deleted
                ):
                    dependencies.add(incarnation.logical_object_id)

            logical = logical_objects[target.logical_object_id]
            if logical.site_mist_id:
                site = await LogicalObject.find_one(
                    LogicalObject.organization_id == organization_id,
                    LogicalObject.object_type == "sites",
                    LogicalObject.current_mist_id == logical.site_mist_id,
                )
                if site is not None and site.id in selected and site.is_deleted:
                    dependencies.add(site.id)
        return sorted(dependencies, key=str)

    @staticmethod
    def _action_type(
        logical: LogicalObject,
        target: ObjectVersion,
        latest: ObjectVersion,
        *,
        force_delete: bool,
    ) -> RestoreActionType | None:
        if force_delete:
            return None if logical.is_deleted else RestoreActionType.DELETE
        if target.is_deleted:
            return None if logical.is_deleted else RestoreActionType.DELETE
        if logical.is_deleted:
            definition = get_definition(logical.scope, logical.object_type)
            if definition is not None and not definition.is_list:
                return RestoreActionType.UPDATE
            return RestoreActionType.CREATE
        if target.id == latest.id:
            return None
        return RestoreActionType.UPDATE

    @staticmethod
    async def _version_at(
        logical_id: PydanticObjectId,
        target_at: datetime,
    ) -> ObjectVersion | None:
        return (
            await ObjectVersion.find(
                ObjectVersion.logical_object_id == logical_id,
                {"observed_at": {"$lte": target_at}},
            )
            .sort("-observed_at")
            .first_or_none()
        )

    @staticmethod
    async def _latest_version(logical_id: PydanticObjectId) -> ObjectVersion | None:
        return await ObjectVersion.find(ObjectVersion.logical_object_id == logical_id).sort("-version").first_or_none()


def order_restore_actions(actions: list[RestoreAction]) -> list[RestoreAction]:
    """Topologically order actions and fail closed on dependency cycles."""
    by_id = {action.logical_object_id: action for action in actions}
    dependencies = {
        action.logical_object_id: {item for item in action.depends_on if item in by_id} for action in actions
    }
    ordered: list[RestoreAction] = []
    while dependencies:
        ready = sorted(
            (object_id for object_id, values in dependencies.items() if not values),
            key=lambda object_id: (
                _action_priority(by_id[object_id].action),
                by_id[object_id].object_type,
                by_id[object_id].object_name,
            ),
        )
        if not ready:
            msg = "Restore dependency graph contains a cycle"
            raise RestorePlanningError(msg)
        for object_id in ready:
            action = by_id[object_id]
            action.order = len(ordered)
            ordered.append(action)
            dependencies.pop(object_id)
            for remaining in dependencies.values():
                remaining.discard(object_id)
    return ordered


def _action_priority(action: RestoreActionType) -> int:
    return {
        RestoreActionType.CREATE: 0,
        RestoreActionType.UPDATE: 1,
        RestoreActionType.DELETE: 2,
    }[action]
