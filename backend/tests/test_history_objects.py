"""Filter translation for the configuration object list."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.api.routes.history import (
    OBJECT_LIST_SORT,
    ObjectListFilters,
    object_list_criteria,
)

ORGANIZATION_ID = PydanticObjectId()


def _criteria(**kwargs: object) -> dict[str, object]:
    return object_list_criteria(ORGANIZATION_ID, ObjectListFilters(**kwargs))


def test_every_query_is_scoped_to_one_organization() -> None:
    assert _criteria()["organization_id"] == ORGANIZATION_ID


def test_deleted_objects_are_excluded_unless_asked_for() -> None:
    assert _criteria()["is_deleted"] is False
    assert "is_deleted" not in _criteria(include_deleted=True)


def test_type_and_site_narrow_the_list() -> None:
    criteria = _criteria(object_type="wlans", site_id="site-a")

    assert criteria["object_type"] == "wlans"
    assert criteria["site_mist_id"] == "site-a"


def test_free_text_matches_name_or_type() -> None:
    criteria = _criteria(q="corp")

    assert criteria["$or"] == [
        {"name": {"$regex": "corp", "$options": "i"}},
        {"object_type": {"$regex": "corp", "$options": "i"}},
        {"current_mist_id": {"$regex": "corp", "$options": "i"}},
        {"site_mist_id": {"$regex": "corp", "$options": "i"}},
    ]


def test_a_blank_term_is_not_a_filter() -> None:
    """An empty search box must not narrow the list to nothing."""
    assert "$or" not in _criteria(q="")
    assert "$or" not in _criteria(q="   ")


def test_a_term_of_regex_syntax_is_matched_literally() -> None:
    """A name containing `.` or `(` is a search term, not a pattern."""
    criteria = _criteria(q="wlan (guest).")

    assert criteria["$or"] == [
        {"name": {"$regex": r"wlan\ \(guest\)\.", "$options": "i"}},
        {"object_type": {"$regex": r"wlan\ \(guest\)\.", "$options": "i"}},
        {"current_mist_id": {"$regex": r"wlan\ \(guest\)\.", "$options": "i"}},
        {"site_mist_id": {"$regex": r"wlan\ \(guest\)\.", "$options": "i"}},
    ]


def test_the_sort_ends_in_a_unique_field() -> None:
    """Without a tie-breaker, paging can repeat or skip an object.

    Two objects may share a type and a name, and MongoDB is free to order them
    differently between the query for one page and the query for the next.
    """
    assert OBJECT_LIST_SORT[-1] == "_id"


def test_object_scope_filter_is_combined_with_the_organization_boundary():
    assert _criteria(scope="org")["scope"] == "org"
    assert _criteria(scope="site")["scope"] == "site"
    assert _criteria(scope="site")["organization_id"] == ORGANIZATION_ID


async def test_facets_aggregate_the_entire_scoped_catalogue(monkeypatch):
    from types import SimpleNamespace  # noqa: PLC0415
    from unittest.mock import AsyncMock  # noqa: PLC0415

    from mist_config_guardian_backend.api.routes.history import object_facets  # noqa: PLC0415
    from mist_config_guardian_backend.models.snapshot import LogicalObject  # noqa: PLC0415

    pipelines = []
    queries = []
    groups = [
        {"_id": {"type": "wlans", "site": "site-a"}, "count": 600},
        {"_id": {"type": "settings", "site": "site-a"}, "count": 1},
        {"_id": {"type": "networktemplates", "site": None}, "count": 3},
    ]

    def aggregate(pipeline):
        pipelines.append(pipeline)
        return SimpleNamespace(to_list=AsyncMock(return_value=groups))

    def find(criteria):
        queries.append(criteria)
        return SimpleNamespace(
            to_list=AsyncMock(return_value=[SimpleNamespace(current_mist_id="site-a", name="Paris")])
        )

    monkeypatch.setattr(LogicalObject, "aggregate", aggregate)
    monkeypatch.setattr(LogicalObject, "find", find)
    result = await object_facets(ORGANIZATION_ID, SimpleNamespace(get=AsyncMock()), None)
    assert pipelines[0][0] == {"$match": {"organization_id": ORGANIZATION_ID, "is_deleted": False}}
    assert queries == [{"organization_id": ORGANIZATION_ID, "object_type": "sites"}]
    assert not any("$limit" in stage for stage in pipelines[0])
    assert result.sites[0].name == "Paris"
    assert result.sites[0].count == 601
    assert next(item.count for item in result.types if item.id == "wlans") == 600


def test_sort_defaults_to_latest_capture_and_uses_only_allowed_fields():
    import pytest  # noqa: PLC0415
    from pydantic import ValidationError  # noqa: PLC0415

    from mist_config_guardian_backend.api.routes.history import object_list_sort  # noqa: PLC0415

    assert object_list_sort(ObjectListFilters()) == ("-updated_at", "_id")
    for key in ("updated_at", "name", "object_type", "site_mist_id", "current_version"):
        assert object_list_sort(ObjectListFilters(sort=key, direction="asc")) == (key, "_id")
        assert object_list_sort(ObjectListFilters(sort=key, direction="desc")) == (f"-{key}", "_id")
    with pytest.raises(ValidationError):
        ObjectListFilters(sort="$where")
