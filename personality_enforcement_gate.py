# -*- coding: utf-8 -*-
"""
Minimal RAW enforcement gate for GPT5Master_personality.json constraints.

Changes (RAW-only):
- No local Path dependency (URL fetch only)
- raw.githubusercontent.com ONLY
- /refs/heads/ is FORBIDDEN (use /main)
- Fail-fast / No silent fail
- Runtime evidence generated (http_status, sha256, load_datetime_jst, raw_url)

Stdlib only
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple


# -------------------------
# Constants / Time
# -------------------------
JST = timezone(timedelta(hours=9))
RAW_PREFIX = "https://raw.githubusercontent.com/"


def _now_jst_iso() -> str:
    return datetime.now(JST).isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -------------------------
# Errors / Results
# -------------------------
class EnforcementError(RuntimeError):
    """Raised when enforcement gate blocks progress."""


@dataclass
class EnforcementResult:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    runtime_evidence: Dict[str, Any] = field(default_factory=dict)


# -------------------------
# RAW fetch
# -------------------------
def _assert_raw_only(url: str) -> None:
    if not isinstance(url, str) or not url.startswith(RAW_PREFIX):
        raise EnforcementError(f"FORBIDDEN SOURCE: only raw.githubusercontent.com allowed: {url}")
    if "/refs/heads/" in url:
        raise EnforcementError(f"FORBIDDEN PATH: use /main instead of /refs/heads/: {url}")


def _http_get(url: str, timeout_sec: int = 15) -> Tuple[int, bytes]:
    _assert_raw_only(url)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "MorinoLink-Personality-Enforcement-Gate/RAW-1.0",
            "Accept": "application/json,text/plain,*/*",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        status = getattr(resp, "status", 200)
        body = resp.read()
        return int(status), body


def _load_json_from_raw(url: str, *, timeout_sec: int = 15) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Returns: (parsed_json, evidence)
    evidence fields:
      - raw_url, http_status, sha256, load_datetime_jst
    """
    status, body = _http_get(url, timeout_sec=timeout_sec)
    if status < 200 or status >= 300:
        raise EnforcementError(f"HTTP ERROR {status}: {url}")

    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - fail-fast required
        raise EnforcementError(f"JSON PARSE FAILED: {url}") from exc

    evidence = {
        "raw_url": url,
        "http_status": status,
        "sha256": _sha256(body),
        "load_datetime_jst": _now_jst_iso(),
    }
    return parsed, evidence


# -------------------------
# Personality checks
# -------------------------
def _detect_triggers(context_text: str, trigger_map: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    hits: List[Tuple[str, str]] = []
    if not context_text or not isinstance(trigger_map, dict):
        return hits
    for category, keywords in trigger_map.items():
        if not isinstance(keywords, list):
            continue
        for keyword in keywords:
            if isinstance(keyword, str) and keyword and (keyword in context_text):
                hits.append((str(category), keyword))
    return hits


def _validate_required_fields(evidence: Dict[str, Any], required_fields: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for f in required_fields:
        if f not in evidence or evidence[f] in (None, "", [], {}):
            missing.append(str(f))
    return missing


def enforce_personality_gate(
    personality_raw_url: str,
    *,
    explicit_approval: bool,
    context_text: str,
    decision_evidence: Optional[Dict[str, Any]] = None,
    timeout_sec: int = 15,
    logger: Optional[logging.Logger] = None,
) -> EnforcementResult:
    """
    Enforce GPT5Master_personality.json constraints (RAW-only).

    Checks:
    - hard_constraint_enforcement.default_policy == "No-Go"
    - explicit approval required (No-Go exception gate)
    - decision_evidence_policy.triggers => evidence required
    - decision_evidence_policy.required_fields validated
    - authority.no_silent_fail => logs recorded when blocked
    """

    logs: List[str] = []
    reasons: List[str] = []
    log = logger or logging.getLogger(__name__)

    def record(message: str) -> None:
        logs.append(message)
        try:
            log.info(message)
        except Exception:
            # no_silent_fail: logging must not crash run
            pass

    runtime_evidence: Dict[str, Any] = {
        "gate": "personality_enforcement_gate_raw_only",
        "run_datetime_jst": _now_jst_iso(),
        "inputs": {
            "personality_raw_url": personality_raw_url,
            "explicit_approval": bool(explicit_approval),
            "timeout_sec": int(timeout_sec),
        },
    }

    try:
        # 1) Load RAW personality (fail-fast)
        personality, fetch_ev = _load_json_from_raw(personality_raw_url, timeout_sec=timeout_sec)
        runtime_evidence["fetch"] = fetch_ev
        record("personality json loaded successfully (RAW)")

        hard_constraint = personality["hard_constraint_enforcement"]
        evidence_policy = personality["decision_evidence_policy"]
        authority = personality["authority"]

        # 2) No-Go enforcement
        default_policy = hard_constraint["default_policy"]
        if default_policy != "No-Go":
            raise EnforcementError("default_policy is not No-Go; enforcement requires No-Go")

        if not explicit_approval:
            reasons.append("explicit approval is required to proceed")
            record("blocked: missing explicit approval")

        # 3) Decision Evidence required_fields must be complete (if provided)
        required_fields = evidence_policy.get("required_fields", [])
        if decision_evidence is not None:
            if not isinstance(decision_evidence, dict):
                raise EnforcementError("decision_evidence must be an object")
            missing = _validate_required_fields(decision_evidence, required_fields)
            if missing:
                reasons.append(f"decision evidence missing fields: {missing}")
                record("blocked: decision evidence missing required fields")

        # 4) Trigger detection => evidence required
        triggers = evidence_policy.get("triggers", {})
        trigger_hits = _detect_triggers(context_text, triggers)

        if trigger_hits and decision_evidence is None:
            reasons.append(f"decision evidence required due to triggers: {trigger_hits}")
            record("blocked: triggers detected without evidence")

        if trigger_hits and decision_evidence is not None:
            missing = _validate_required_fields(decision_evidence, required_fields)
            if missing:
                reasons.append(f"decision evidence missing fields: {missing}")
                record("blocked: trigger evidence missing required fields")

        # 5) no_silent_fail logging
        if isinstance(authority, dict) and authority.get("no_silent_fail") is True and reasons:
            record("no_silent_fail: enforcement failure recorded")

    except EnforcementError as exc:
        record(f"enforcement error: {exc}")
        runtime_evidence["blocked"] = True
        runtime_evidence["error"] = str(exc)
        return EnforcementResult(False, [str(exc)], logs, runtime_evidence)
    except Exception as exc:  # noqa: BLE001
        record(f"unexpected error: {exc}")
        runtime_evidence["blocked"] = True
        runtime_evidence["error"] = str(exc)
        return EnforcementResult(False, [str(exc)], logs, runtime_evidence)

    allowed = not reasons
    return EnforcementResult(allowed, reasons, logs, runtime_evidence)


__all__ = [
    "EnforcementError",
    "EnforcementResult",
    "enforce_personality_gate",
]
