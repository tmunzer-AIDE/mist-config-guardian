"""Secret-safe AI assistance built on top of the deterministic diff.

Every prompt is assembled here from an already-redacted
:class:`~mist_config_guardian_backend.schemas.diff.ConfigurationDiff`, so the
provider only ever receives field paths, classifications, and non-secret
display values. A final guard rejects any evidence package that still contains
encrypted material.
"""

import json
import time
from dataclasses import dataclass
from typing import Final

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.integrations.ai_provider import (
    AiCompletion,
    AiMessage,
    AiProvider,
    AiProviderError,
)
from mist_config_guardian_backend.models.application_configuration import AiRequestAudit
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.schemas.ai import (
    AiAssistCard,
    AiDiffFollowupResponse,
    AiDiffSummaryResponse,
)
from mist_config_guardian_backend.schemas.diff import ConfigurationDiff, DiffEntry
from mist_config_guardian_backend.services.application_configuration import (
    AiProviderFactory,
    AiPurpose,
    AiRequestRecord,
    AiRuntimeConfiguration,
    ApplicationConfigurationError,
    ApplicationConfigurationService,
    build_openai_compatible_provider,
)
from mist_config_guardian_backend.services.diff import ENCRYPTED_MARKER, FINGERPRINT_MARKER

MAX_EVIDENCE_ENTRIES: Final = 120
SUMMARY_CACHE_TTL_SECONDS: Final = 900
SUMMARY_CACHE_SIZE: Final = 128

_SUMMARY_SYSTEM_PROMPT: Final = (
    "You explain network configuration changes to an engineer. You receive a "
    "deterministic, redacted diff: field paths, change kinds, and non-secret "
    "display values only. Never speculate about values you were not given and "
    "never ask for secrets. Answer with a JSON object containing: 'summary' (a "
    "short paragraph describing what this version changes), 'intent' (an array "
    "of short strings describing the apparent intent), and 'flags' (an array of "
    "objects with 'level' of crit, warn, or info, 'text', and 'ref' set to one "
    "of the supplied field paths)."
)

_FOLLOWUP_SYSTEM_PROMPT: Final = (
    "You answer one question about a single deterministic, redacted "
    "configuration diff. Use only the supplied evidence. If the evidence does "
    "not contain the answer, say so plainly. Reply with plain text, no JSON, "
    "and never request or infer secret values."
)

_SECRET_PLACEHOLDER: Final = "redacted"  # noqa: S105 - evidence placeholder, not a credential
_EVIDENCE_NOTE: Final = "Secrets were removed before this request; entries marked secret carry no values."


class AiAssistError(RuntimeError):
    """Raised when AI assistance cannot produce a result."""


class AiUnavailableError(AiAssistError):
    """Raised when AI assistance is disabled or incompletely configured."""


class AiEvidenceError(AiAssistError):
    """Raised when an evidence package still contains protected material."""


class AiAuditRecorder:
    """Persist one :class:`AiRequestAudit` per outbound provider call."""

    async def record(self, record: AiRequestRecord) -> None:
        """Insert the audit record, never including prompt text."""
        await AiRequestAudit(
            purpose=record.purpose,
            organization_id=record.organization_id,
            user_id=record.user_id,
            subject_id=record.subject_id,
            base_url=record.base_url,
            model=record.model,
            request_tokens=record.request_tokens,
            response_tokens=record.response_tokens,
            duration_ms=record.duration_ms,
            succeeded=record.succeeded,
            error=record.error,
            redaction_applied=record.redaction_applied,
        ).insert()


@dataclass
class _CacheEntry:
    response: AiDiffSummaryResponse
    expires_at: float


_SUMMARY_CACHE: dict[tuple[str, str, str, str], _CacheEntry] = {}


def _cache_get(key: tuple[str, str, str, str]) -> AiDiffSummaryResponse | None:
    entry = _SUMMARY_CACHE.get(key)
    if entry is None:
        return None
    if entry.expires_at <= time.monotonic():
        _SUMMARY_CACHE.pop(key, None)
        return None
    return entry.response


def _cache_put(key: tuple[str, str, str, str], response: AiDiffSummaryResponse) -> None:
    if len(_SUMMARY_CACHE) >= SUMMARY_CACHE_SIZE:
        _SUMMARY_CACHE.pop(next(iter(_SUMMARY_CACHE)), None)
    _SUMMARY_CACHE[key] = _CacheEntry(
        response=response,
        expires_at=time.monotonic() + SUMMARY_CACHE_TTL_SECONDS,
    )


def _entry_evidence(entry: DiffEntry) -> dict[str, object]:
    evidence: dict[str, object] = {
        "field": entry.field,
        "kind": entry.kind.value,
        "section": entry.section,
        "note": entry.note,
    }
    if entry.notable:
        evidence["notable"] = True
    if entry.reordered:
        evidence["reordered"] = True
    if entry.secret:
        evidence["secret"] = True
        evidence["before"] = _SECRET_PLACEHOLDER
        evidence["after"] = _SECRET_PLACEHOLDER
        return evidence
    evidence["before"] = entry.before
    evidence["after"] = entry.after
    return evidence


def _selected_entries(diff: ConfigurationDiff, limit: int) -> list[DiffEntry]:
    seen: set[int] = set()
    selected: list[DiffEntry] = []
    for entry in [*diff.notable, *diff.entries]:
        if id(entry) not in seen:
            seen.add(id(entry))
            selected.append(entry)
    for section in diff.sections:
        for entry in section.entries:
            if id(entry) not in seen:
                seen.add(id(entry))
                selected.append(entry)
    return selected[:limit]


def build_evidence(diff: ConfigurationDiff, *, limit: int = MAX_EVIDENCE_ENTRIES) -> dict[str, object]:
    """Build the bounded, redacted evidence package sent to the provider."""
    entries = _selected_entries(diff, limit)
    evidence: dict[str, object] = {
        "counts": diff.counts.model_dump(),
        "sections": [
            {
                "name": section.name,
                "path": section.path,
                "changed": section.counts.changed,
                "added": section.counts.added,
                "modified": section.counts.modified,
                "removed": section.counts.removed,
                "notable": section.notable,
            }
            for section in diff.sections
        ],
        "changes": [_entry_evidence(entry) for entry in entries],
        "changes_omitted": max(diff.counts.changed - len(entries), 0),
        "note": _EVIDENCE_NOTE,
    }
    return _guard(evidence)


def _guard(evidence: dict[str, object]) -> dict[str, object]:
    serialized = json.dumps(evidence, default=str)
    if ENCRYPTED_MARKER in serialized or FINGERPRINT_MARKER in serialized:
        msg = "The evidence package still contains protected material and was not sent"
        raise AiEvidenceError(msg)
    return evidence


def build_summary_messages(diff: ConfigurationDiff) -> list[AiMessage]:
    """Build the summary prompt from redacted diff evidence only."""
    evidence = build_evidence(diff)
    return [
        AiMessage(role="system", content=_SUMMARY_SYSTEM_PROMPT),
        AiMessage(role="user", content=json.dumps(evidence, separators=(",", ":"), default=str)),
    ]


def build_followup_messages(diff: ConfigurationDiff, question: str) -> list[AiMessage]:
    """Build a follow-up prompt bound to one fixed diff and one question."""
    evidence = build_evidence(diff)
    payload = {"evidence": evidence, "question": question}
    return [
        AiMessage(role="system", content=_FOLLOWUP_SYSTEM_PROMPT),
        AiMessage(role="user", content=json.dumps(payload, separators=(",", ":"), default=str)),
    ]


def parse_summary(content: str) -> tuple[str, list[AiAssistCard]]:
    """Split a provider response into a summary paragraph and display cards."""
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return content.strip(), []
    if not isinstance(payload, dict):
        return content.strip(), []
    summary = str(payload.get("summary") or "").strip() or content.strip()
    cards = [*_intent_cards(payload.get("intent")), *_flag_cards(payload.get("flags"))]
    return summary, cards


def _intent_cards(intent: object) -> list[AiAssistCard]:
    if not isinstance(intent, list):
        return []
    cards: list[AiAssistCard] = []
    for item in intent:
        text = item if isinstance(item, str) else str(item)
        if text.strip():
            cards.append(AiAssistCard(kind="intent", level="info", text=text.strip()))
    return cards


def _flag_cards(flags: object) -> list[AiAssistCard]:
    if not isinstance(flags, list):
        return []
    cards: list[AiAssistCard] = []
    for item in flags:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        level = str(item.get("level") or "warn").lower()
        reference = item.get("ref")
        cards.append(
            AiAssistCard(
                kind="flag",
                level=level if level in {"info", "warn", "crit"} else "warn",
                text=text,
                field=str(reference) if isinstance(reference, str) and reference else None,
            )
        )
    return cards


@dataclass(frozen=True)
class DiffSubject:
    """Identity of the comparison an assistance request is bound to."""

    organization_id: PydanticObjectId
    from_version_id: PydanticObjectId
    to_version_id: PydanticObjectId
    user_id: PydanticObjectId | None = None

    @property
    def subject_id(self) -> str:
        """Return a stable identifier for the compared pair."""
        return f"{self.from_version_id}->{self.to_version_id}"


class AiAssistService:
    """Produce diff summaries and follow-up answers from redacted evidence."""

    def __init__(
        self,
        configuration: ApplicationConfigurationService,
        settings: Settings | None = None,
        recorder: AiAuditRecorder | None = None,
        provider_factory: AiProviderFactory | None = None,
    ) -> None:
        self._configuration = configuration
        self._settings = settings or get_settings()
        self._recorder = recorder or AiAuditRecorder()
        self._provider_factory: AiProviderFactory = provider_factory or build_openai_compatible_provider

    async def summarize_diff(
        self,
        diff: ConfigurationDiff,
        subject: DiffSubject,
        *,
        regenerate: bool = False,
    ) -> AiDiffSummaryResponse:
        """Summarise a comparison, reusing a recent identical summary."""
        runtime = await self._runtime()
        cache_key = (
            str(subject.organization_id),
            str(subject.from_version_id),
            str(subject.to_version_id),
            runtime.model,
        )
        if not regenerate:
            cached = _cache_get(cache_key)
            if cached is not None:
                return cached.model_copy(update={"cached": True})
        messages = build_summary_messages(diff)
        completion = await self._call(runtime, messages, subject, purpose="diff_summary", json_object=True)
        summary, cards = parse_summary(completion.content)
        response = AiDiffSummaryResponse(
            summary=summary,
            model=completion.model,
            generated_at=utc_now(),
            cards=cards,
            duration_ms=completion.duration_ms,
        )
        _cache_put(cache_key, response)
        return response

    async def answer_followup(
        self,
        diff: ConfigurationDiff,
        subject: DiffSubject,
        question: str,
    ) -> AiDiffFollowupResponse:
        """Answer one question against a fixed comparison."""
        runtime = await self._runtime()
        messages = build_followup_messages(diff, question)
        completion = await self._call(runtime, messages, subject, purpose="diff_followup", json_object=False)
        return AiDiffFollowupResponse(
            question=question,
            answer=completion.content.strip(),
            model=completion.model,
            generated_at=utc_now(),
            duration_ms=completion.duration_ms,
        )

    async def _runtime(self) -> AiRuntimeConfiguration:
        try:
            runtime = await self._configuration.ai_runtime()
        except ApplicationConfigurationError as exc:
            raise AiUnavailableError(str(exc)) from exc
        if runtime is None:
            msg = "AI assistance is disabled; deterministic comparison remains available"
            raise AiUnavailableError(msg)
        return runtime

    async def _call(
        self,
        runtime: AiRuntimeConfiguration,
        messages: list[AiMessage],
        subject: DiffSubject,
        *,
        purpose: AiPurpose,
        json_object: bool,
    ) -> AiCompletion:
        provider = self._build_provider(runtime)
        started = time.perf_counter()
        try:
            completion = await provider.complete(
                messages,
                max_tokens=runtime.max_response_tokens,
                json_object=json_object,
            )
        except AiProviderError as exc:
            await self._audit(
                runtime,
                subject,
                purpose=purpose,
                duration_ms=int((time.perf_counter() - started) * 1000),
                succeeded=False,
                error=str(exc),
            )
            raise
        finally:
            await provider.aclose()
        await self._audit(
            runtime,
            subject,
            purpose=purpose,
            duration_ms=completion.duration_ms,
            succeeded=True,
            request_tokens=completion.request_tokens,
            response_tokens=completion.response_tokens,
        )
        return completion

    def _build_provider(self, runtime: AiRuntimeConfiguration) -> AiProvider:
        return self._provider_factory(
            base_url=runtime.base_url,
            model=runtime.model,
            api_key=runtime.api_key,
            timeout=self._settings.ai_request_timeout_seconds,
            max_response_tokens=runtime.max_response_tokens,
        )

    async def _audit(  # noqa: PLR0913 - one audit record shape
        self,
        runtime: AiRuntimeConfiguration,
        subject: DiffSubject,
        *,
        purpose: AiPurpose,
        duration_ms: int,
        succeeded: bool,
        request_tokens: int | None = None,
        response_tokens: int | None = None,
        error: str | None = None,
    ) -> None:
        await self._recorder.record(
            AiRequestRecord(
                purpose=purpose,
                organization_id=subject.organization_id,
                user_id=subject.user_id,
                subject_id=subject.subject_id,
                base_url=runtime.base_url,
                model=runtime.model,
                request_tokens=request_tokens,
                response_tokens=response_tokens,
                duration_ms=duration_ms,
                succeeded=succeeded,
                error=error,
                redaction_applied=True,
            )
        )
