"""Field-level protection for secrets returned in Mist configuration."""

from collections.abc import Mapping, Sequence

from mist_config_guardian_backend.security.credentials import CredentialVault

_ENCRYPTED_MARKER = "$encrypted"
_FINGERPRINT_MARKER = "$fingerprint"
_REDACTED = "********"


def is_protected(value: object) -> bool:
    """Report whether a value is a protected-secret marker.

    Presence of the marker is what matters, not the shape of the surrounding
    dictionary: keying off an exact single-key match would silently return
    ciphertext the moment a sibling key such as a fingerprint is added.
    """
    return isinstance(value, Mapping) and isinstance(value.get(_ENCRYPTED_MARKER), str)


def protected_fingerprint(value: object) -> str | None:
    """Return a protected value's comparison fingerprint, when it carries one."""
    if not isinstance(value, Mapping):
        return None
    fingerprint = value.get(_FINGERPRINT_MARKER)
    return fingerprint if isinstance(fingerprint, str) else None


def protect_configuration(
    configuration: Mapping[str, object],
    vault: CredentialVault,
    *,
    sensitive_fields: frozenset[str],
) -> dict[str, object]:
    """Encrypt registry-declared sensitive values before persistence."""

    def protect(value: object, path: str, field_name: str | None = None) -> object:
        if field_name is not None and field_name.lower() in sensitive_fields:
            if isinstance(value, str) and value:
                return {
                    _ENCRYPTED_MARKER: vault.encrypt_for_context(
                        value,
                        context=f"snapshot:{path}",
                    ),
                    # Lets a diff decide whether two protected values are equal
                    # without decrypting either of them.
                    _FINGERPRINT_MARKER: vault.fingerprint(value),
                }
            return value
        if isinstance(value, Mapping):
            return {
                str(key): protect(
                    child,
                    f"{path}.{key}" if path else str(key),
                    str(key),
                )
                for key, child in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [protect(child, f"{path}.{index}") for index, child in enumerate(value)]
        return value

    return {str(key): protect(value, str(key), str(key)) for key, value in configuration.items()}


def reveal_configuration(
    configuration: Mapping[str, object],
    vault: CredentialVault,
) -> dict[str, object]:
    """Decrypt protected fields for hashing, diffing, or delegated restore."""

    def reveal(value: object, path: str) -> object:
        if isinstance(value, Mapping):
            if is_protected(value):
                encrypted = str(value[_ENCRYPTED_MARKER])
                return vault.decrypt_for_context(encrypted, context=f"snapshot:{path}")
            return {str(key): reveal(child, f"{path}.{key}" if path else str(key)) for key, child in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [reveal(child, f"{path}.{index}") for index, child in enumerate(value)]
        return value

    return {str(key): reveal(value, str(key)) for key, value in configuration.items()}


def redact_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    """Replace encrypted values with a safe API placeholder."""

    def redact(value: object) -> object:
        if isinstance(value, Mapping):
            if is_protected(value):
                return _REDACTED
            return {str(key): redact(child) for key, child in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [redact(child) for child in value]
        return value

    return {str(key): redact(value) for key, value in configuration.items()}
