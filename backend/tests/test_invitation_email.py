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


def test_html_injection_in_inviter_is_escaped() -> None:
    """Script injection in inviter name is escaped in HTML, left verbatim in text."""
    malicious_inviter = "<img src=x onerror=alert(1)>"

    message = build_invitation_message(
        app_name="Mist Config Guardian",
        inviter=malicious_inviter,
        activation_link="https://guardian.example.com/accept-invitation#token=x",
        expires_in_days=7,
    )

    # In HTML, the tag must be escaped so it won't execute
    assert "<img" not in message.html
    assert "&lt;img" in message.html
    assert "&lt;img src=x onerror=alert(1)&gt;" in message.html

    # In text, it appears verbatim (not escaped)
    assert malicious_inviter in message.text


def test_html_injection_in_app_name_is_escaped() -> None:
    """Special characters in app_name are escaped in HTML."""
    app_name_with_html = "My & <Dangerous> App"

    message = build_invitation_message(
        app_name=app_name_with_html,
        inviter="Alice",
        activation_link="https://guardian.example.com/accept-invitation#token=x",
        expires_in_days=7,
    )

    # In HTML, & and < must be escaped
    assert "My &amp; &lt;Dangerous&gt; App" in message.html
    # Original unescaped version must not be in HTML
    assert "My & <Dangerous> App" not in message.html

    # In text, it appears verbatim
    assert app_name_with_html in message.text


def test_double_quote_in_inviter_does_not_break_attribute() -> None:
    """Double quotes in inviter don't break out of href attribute."""
    inviter_with_quote = 'Alice "Admin" Bob'

    message = build_invitation_message(
        app_name="Mist Config Guardian",
        inviter=inviter_with_quote,
        activation_link="https://guardian.example.com/accept-invitation#token=x",
        expires_in_days=7,
    )

    # The attribute should remain intact
    assert 'href="https://guardian.example.com/accept-invitation#token=x"' in message.html
    # No broken attribute syntax
    assert 'href="' in message.html
    assert message.html.count('href="') == 1  # Only one href attribute
