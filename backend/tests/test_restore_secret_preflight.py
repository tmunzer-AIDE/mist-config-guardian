"""Only all-asterisk secret placeholders block a restore plan."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_planner import unavailable_secret_errors
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import protect_configuration

VAULT = CredentialVault(Settings())
SENSITIVE = get_definition("org", "networktemplates").sensitive_fields


def _action(
    configuration: dict[str, object],
    *,
    action: RestoreActionType = RestoreActionType.UPDATE,
    object_type: str = "networktemplates",
) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=action,
        scope="org",
        object_type=object_type,
        object_name="DNT-NTR",
        current_mist_id="mist-1",
        protected_configuration=protect_configuration(
            configuration,
            VAULT,
            sensitive_fields=SENSITIVE,
        ),
        depends_on=[],
    )


def test_a_masked_secret_is_reported_against_the_object_that_carries_it() -> None:
    action = _action({"radius_config": {"auth_servers": [{"host": "10.0.0.1", "secret": "********"}]}})

    assert unavailable_secret_errors([action], VAULT) == [
        "DNT-NTR requires unavailable secret values: radius_config.auth_servers.0.secret"
    ]


def test_every_masked_location_is_named_once_in_a_stable_order() -> None:
    action = _action(
        {
            "radius_config": {
                "acct_servers": [{"secret": "********"}],
                "auth_servers": [{"secret": "********"}],
            }
        }
    )

    assert unavailable_secret_errors([action], VAULT) == [
        (
            "DNT-NTR requires unavailable secret values: "
            "radius_config.acct_servers.0.secret, radius_config.auth_servers.0.secret"
        )
    ]


def test_a_secret_that_survived_capture_is_not_an_error() -> None:
    action = _action({"radius_config": {"auth_servers": [{"secret": "a-real-shared-secret"}]}})

    assert unavailable_secret_errors([action], VAULT) == []


def test_missing_empty_and_null_sensitive_fields_are_not_unavailable() -> None:
    action = _action(
        {
            "radius_config": {
                "auth_servers": [
                    {"host": "10.0.0.1"},
                    {"host": "10.0.0.2", "secret": ""},
                    {"host": "10.0.0.3", "secret": None},
                ]
            },
            "switch_mgmt": {"root_password": ""},
        }
    )

    assert unavailable_secret_errors([action], VAULT) == []


def test_a_delete_needs_no_secret() -> None:
    """A delete sends no configuration, so a mask in the version cannot reach Mist."""
    action = _action(
        {"radius_config": {"auth_servers": [{"secret": "********"}]}},
        action=RestoreActionType.DELETE,
    )

    assert unavailable_secret_errors([action], VAULT) == []


def test_a_secret_that_will_not_decrypt_is_reported_rather_than_raised() -> None:
    """Planning describes the action that cannot run; it does not fail outright.

    A snapshot encrypted under a key this deployment no longer holds cannot be
    replayed, which is a preflight matter. Letting the decryption error escape
    would fail the whole planning request, and a plan is how anyone would find
    out which object is affected.
    """
    action = _action({"radius_config": {"auth_servers": [{"secret": "a-real-shared-secret"}]}})
    other_key = CredentialVault(Settings(environment="test", credential_encryption_key="another-key"))

    assert unavailable_secret_errors([action], other_key) == [
        "DNT-NTR has secrets that cannot be decrypted with the current key"
    ]


def test_an_unregistered_type_is_reported_rather_than_skipped() -> None:
    action = _action({}, object_type="not-a-real-type")

    assert unavailable_secret_errors([action], VAULT) == ["Unsupported restore type: org:not-a-real-type"]
