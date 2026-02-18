# -*- coding: utf-8 -*-
"""
MorinoLink RAW Enforcement Gate (STRICT RAW-ONLY EDITION)

Enforces GPT5Master_personality.json constraints.

Guarantees:
- RAW fetch ONLY (no local file load)
- raw.githubusercontent.com ONLY
- /refs/heads/ is FORBIDDEN (use /main)
- Fail-fast
- No silent fail
- Runtime evidence generated (http_status, sha256, load_datetime_jst, raw_url)

Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple


# =========================================================
# Time
# =========================================================

JST = timezone(timedelta(hours=9))
RAW_PREFIX = "https://raw.githubusercontent.com/"


def _now_jst() -> str:
    return datetime.now(JST).isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# =========================================================
# Errors / Result
# =========================================================

class EnforcementError(RuntimeError):
    """Raised when enforcement gate blocks progress."""


@dataclass
class EnforcementResult:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    runtime_evidence: Dict[str, Any] = field(default_factory=dict)


# =========================================================
# RAW JSON Loader
# =========================================================

def _assert_raw(url: str) -> None:
    if not isinstance(url, str) or not url.startswith(RAW_PREFIX):
        raise EnforcementError("FORBIDDEN SOURCE: only raw.githubusercontent.com allowed")

    if "/refs/heads/" in url:
        raise EnforcementError("FORBIDDEN FORMAT: use /main instead of /refs/heads/")


def _fetch_json_raw(url: str, timeout_sec: int = 15) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    _assert_raw(url)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "MorinoLink-PersonalityGate/RAW-STRICT",
            "Accept": "application/json,text/plain,*/*",
        },
        method="GET",
    )

    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        status = getattr(resp, "status", 200)
        body = resp.read()

    if status < 200 or status >= 300:
        raise EnforcementError(f"HTTP ERROR {status}: {url}")

    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise EnforcementError(f"JSON PARSE FAILED: {url}") from exc

    evidence = {
        "raw_url": url,
        "http_status": status,
        "sha256": _sha256(body),
        "load_datetime_jst": _now_jst(),
    }

    return parsed, evidence


# =========================================================
# Helpers
# =========================================================

def _detect_triggers(
    context_text: str,
    trigger_map: Dict[str, List[str]],
) -> List[Tuple[str, str]]:
    hits: List[Tuple[str, str]] = []
    if not context_text or not isinstance(trigger_map, dict):
        return hits

    for category, keywords in trigger_map.items():
        if not isinstance(keywords, list):
            continue
        for keyword in keywords:
            if isinstance(keyword, str) and keyword and keyword in context_text:
                hits.append((str(category), keyword))
    return hits


def _validate_required_fields(
    evidence: Dict[str, Any],
    required_fields: Iterable[str],
) -> List[str]:
    missing = []
    for field in required_fields:
        if field not in evidence or evidence[field] in (None, "", [], {}):
            missing.append(str(field))
    return missing


# =========================================================
# Main Enforcement
# =========================================================

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
    Enforce GPT5Master_personality.json constraints from RAW GitHub.

    personality_raw_url must be:
    https://raw.githubusercontent.com/.../main/...json
    """

    logs: List[str] = []
    reasons: List[str] = []
    log = logger or logging.getLogger(__name__)

    def record(message: str) -> None:
        logs.append(message)
        try:
            log.info(message)
        except Exception:
            pass  # no silent crash due to logging failure

    runtime_evidence: Dict[str, Any] = {
        "gate_type": "RAW_STRICT",
        "run_datetime_jst": _now_jst(),
        "personality_raw_url": personality_raw_url,
    }

    try:
        # 1) Load personality via RAW only
        personality, ev = _fetch_json_raw(personality_raw_url, timeout_sec=timeout_sec)
        runtime_evidence["personality_fetch"] = ev
        record("personality json loaded from RAW")

        hard_constraint = personality["hard_constraint_enforcement"]
        evidence_policy = personality["decision_evidence_policy"]
        authority = personality["authority"]

        # 2) No-Go enforcement
        default_policy = hard_constraint.get("default_policy")
        if default_policy != "No-Go":
            raise EnforcementError("default_policy must be No-Go")

        if not explicit_approval:
            reasons.append("explicit approval required (No-Go policy)")
            record("blocked: missing explicit approval")

        # 3) Trigger detection
        triggers = evidence_policy.get("triggers", {})
        required_fields = evidence_policy.get("required_fields", [])

        trigger_hits = _detect_triggers(context_text, triggers)

        if trigger_hits and decision_evidence is None:
            reasons.append(f"decision evidence required due to triggers: {trigger_hits}")
            record("blocked: triggers detected without evidence")

        if decision_evidence is not None:
            if not isinstance(decision_evidence, dict):
                raise EnforcementError("decision_evidence must be object")

            missing = _validate_required_fields(decision_evidence, required_fields)
            if missing:
                reasons.append(f"decision evidence missing fields: {missing}")
                record("blocked: decision evidence missing required fields")

        # 4) no_silent_fail enforcement
        if authority.get("no_silent_fail") is True and reasons:
            record("no_silent_fail: enforcement failure recorded")

    except EnforcementError as exc:
        record(f"BLOCKED: {exc}")
        runtime_evidence["error"] = str(exc)
        return EnforcementResult(False, [str(exc)], logs, runtime_evidence)

    except Exception as exc:
        record(f"UNEXPECTED ERROR: {exc}")
        runtime_evidence["error"] = str(exc)
        return EnforcementResult(False, [str(exc)], logs, runtime_evidence)

    allowed = not reasons
    return EnforcementResult(allowed, reasons, logs, runtime_evidence)


__all__ = [
    "EnforcementError",
    "EnforcementResult",
    "enforce_personality_gate",
]
