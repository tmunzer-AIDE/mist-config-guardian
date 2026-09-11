"""The invitation message and the link it carries."""

from mist_config_guardian_backend.services.invitation_email import (
    activation_url,
    build_invitation_message,
)

TOKEN = "s3cr3t-token-value"


def test_the_token_travels_in_the_fragment() -> None:
    """A query string reaches ingress logs, history, and Referer headers."""
    url = activation_url("https://guardian.example.com", TOKEN)

    assert url == f"https://guardian.example.com/accept-invitation#token={TOKEN}"
    assert "?" not in url


def test_a_trailing_slash_on_the_base_does_not_double() -> None:
    assert activation_url("https://guardian.example.com/", TOKEN).startswith(
        "https://guardian.example.com/accept-invitation"
    )


def test_a_token_needing_escaping_is_encoded() -> None:
    url = activation_url("https://guardian.example.com", "a b+c/d")

    assert " " not in url
    assert url.endswith("#token=a%20b%2Bc%2Fd")


def test_the_message_states_the_inviter_the_link_and_the_expiry() -> None:
    link = activation_url("https://guardian.example.com", TOKEN)

    message = build_invitation_message(
        app_name="Mist Config Guardian",
        inviter="Thomas Munzer",
        activation_link=link,
        expires_in_days=7,
    )

    assert "Mist Config Guardian" in message.subject
    assert "Thomas Munzer" in message.text
    assert link in message.text
    assert link in message.html
    assert "7 days" in message.text


def test_an_unattributed_invitation_still_reads_sensibly() -> None:
    message = build_invitation_message(
        app_name="Mist Config Guardian",
        inviter=None,
        activation_link="https://guardian.example.com/accept-invitation#token=x",
        expires_in_days=7,
    )

    assert "None" not in message.text
