"""The sendscore.verdict/v1 report. New keys may appear in this version."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

Status = Literal["pass", "warn", "fail", "info", "skipped"]
Category = Literal["auth", "unsub", "struct", "content", "delivery", "changes"]
Who = Literal["you", "provider"]


Message = TypedDict(
    "Message",
    {
        "received_at": str,
        "from": str,
        "subject": str,
        "message_id": str,
        "size_bytes": int,
    },
)


class Fix(TypedDict):
    who: Who
    text: str


class _CheckOptional(TypedDict, total=False):
    detail: str
    evidence: dict[str, Any]
    fix: Fix
    docs: str
    reason: str


class Check(_CheckOptional):
    id: str
    category: Category
    status: Status
    title: str


class TopFix(TypedDict):
    check: str
    who: Who
    fix: str


class _ChangeOptional(TypedDict, total=False):
    worsened: str


class Change(_ChangeOptional):
    field: str
    before: Any
    after: Any


class _FingerprintOptional(TypedDict, total=False):
    remote_ip: str
    ptr: str


class Fingerprint(_FingerprintOptional):
    dkim_domains: list[str]
    dkim_selectors: list[str]
    return_path_domain: str
    list_unsubscribe: bool
    one_click: bool
    link_hosts: list[str]
    html_bytes: int
    links: int
    images: int
    auth: dict[str, Status] | None


class _VerdictOptional(TypedDict, total=False):
    id: str
    publication: str
    fingerprint: Fingerprint


class Verdict(_VerdictOptional):
    schema: str
    message: Message
    verdict: Status
    ready_to_send: bool
    summary: str
    top_fixes: list[TopFix]
    checks: list[Check]
    changes: list[Change]
    explanation: str | None
    note: str


class DiffResult(TypedDict):
    before: str
    after: str
    changes: list[Change]
