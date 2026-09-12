"""The invitation message, and the activation link it carries.

The link puts the token in the URL fragment. A query string is carried in the
request line and lands in ingress logs, proxy logs, browser history, and
``Referer`` headers on any outbound link; a fragment is never sent to a server
at all.
"""

import html
from dataclasses import dataclass
from urllib.parse import quote

ACTIVATION_PATH = "/accept-invitation"


def activation_url(base_url: str, token: str) -> str:
    """Return the link an invitee follows to choose a password."""
    return f"{base_url.rstrip('/')}{ACTIVATION_PATH}#token={quote(token, safe='')}"


@dataclass(frozen=True, slots=True)
class InvitationMessage:
    """One rendered invitation, in both the parts a mail client may show."""

    subject: str
    text: str
    html: str


def build_invitation_message(
    *,
    app_name: str,
    inviter: str | None,
    activation_link: str,
    expires_in_days: int,
) -> InvitationMessage:
    """Render the invitation. Every value here is supplied, never AI-written."""
    who = f"{inviter} has invited you" if inviter else "You have been invited"
    subject = f"Your invitation to {app_name}"
    text = (
        f"{who} to {app_name}.\n\n"
        f"Choose a password to activate your account:\n{activation_link}\n\n"
        f"This link expires in {expires_in_days} days. "
        "If you were not expecting this invitation, you can ignore this message."
    )

    # Escape values for HTML to prevent stored injection
    who_html = html.escape(who)
    app_name_html = html.escape(app_name)
    activation_link_html = html.escape(activation_link)

    html_content = (
        f"<p>{who_html} to {app_name_html}.</p>"
        f'<p><a href="{activation_link_html}">Choose a password to activate your account</a></p>'
        f"<p>This link expires in {expires_in_days} days. "
        "If you were not expecting this invitation, you can ignore this message.</p>"
    )
    return InvitationMessage(subject=subject, text=text, html=html_content)
