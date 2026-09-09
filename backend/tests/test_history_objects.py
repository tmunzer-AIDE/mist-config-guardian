"""Filter translation for the configuration object list."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.api.routes.history import (
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
    ]
