"""Deep links are built against what the browser application actually reads."""

import pytest

from mist_config_guardian_backend.models.notification import NotificationTarget
from mist_config_guardian_backend.services.deep_links import CONSUMED_PARAMETERS, SETTINGS_TABS, deep_link


def test_a_link_carries_only_the_parameters_its_page_reads() -> None:
    assert deep_link("changes", group="g1") == {"group": "g1"}
    assert deep_link("restore", operation="op1", step="authorize") == {"operation": "op1", "step": "authorize"}
    assert deep_link("settings", tab="organizations") == {"tab": "organizations"}


def test_absent_values_are_dropped_rather_than_sent_as_the_string_none() -> None:
    """A created object has no earlier version; the link must not say `a=None`."""
    assert deep_link("history", object="o1", a=None, b="v2") == {"object": "o1", "b": "v2"}


def test_a_parameter_the_page_does_not_read_is_refused() -> None:
    """Dropping it silently is exactly the failure this module exists to stop."""
    with pytest.raises(ValueError, match="does not read \\['restoreId'\\]"):
        deep_link("restore", restoreId="op1")


def test_an_unknown_page_is_refused() -> None:
    with pytest.raises(ValueError, match="not a page"):
        deep_link("snapshots", manifest="m1")


def test_a_settings_tab_that_does_not_exist_is_refused() -> None:
    with pytest.raises(ValueError, match="not a settings tab"):
        deep_link("settings", tab="webhooks")


def test_notification_targets_are_all_pages_the_registry_knows() -> None:
    """The enum and the registry describe the same application."""
    assert {target.value for target in NotificationTarget} == set(CONSUMED_PARAMETERS)


def test_the_enum_value_addresses_the_registry_directly() -> None:
    assert deep_link(NotificationTarget.CHANGES, actor="j.mercer") == {"actor": "j.mercer"}


def test_every_settings_tab_the_browser_defines_is_linkable() -> None:
    assert {"organizations", "users", "ai", "health"} == SETTINGS_TABS
