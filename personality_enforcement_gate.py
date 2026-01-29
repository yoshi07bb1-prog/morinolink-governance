"""Minimal enforcement gate for GPT5Master_personality.json constraints."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


class EnforcementError(RuntimeError):
    """Raised when enforcement gate blocks progress."""


@dataclass
class EnforcementResult:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - fail-fast required
        raise EnforcementError(f"failed to load personality json: {path}") from exc


def _detect_triggers(
    context_text: str, trigger_map: Dict[str, List[str]]
) -> List[Tuple[str, str]]:
    hits: List[Tuple[str, str]] = []
    for category, keywords in trigger_map.items():
        for keyword in keywords:
            if keyword in context_text:
                hits.append((category, keyword))
    return hits


def _validate_required_fields(
    evidence: Dict[str, Any], required_fields: Iterable[str]
) -> List[str]:
    missing = []
    for field in required_fields:
        if field not in evidence or evidence[field] in (None, "", []):
            missing.append(field)
    return missing


def enforce_personality_gate(
    personality_path: Path,
    *,
    explicit_approval: bool,
    context_text: str,
    decision_evidence: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None,
) -> EnforcementResult:
    """
    Enforce GPT5Master_personality.json constraints.

    Each check references the corresponding personality definition:
    - hard_constraint_enforcement.default_policy = "No-Go"
    - hard_constraint_enforcement.exception_rule (explicit approval required)
    - decision_evidence_policy.required_fields
    - decision_evidence_policy.triggers (finance/legal/field/strategy)
    - authority.no_silent_fail = true
    """

    logs: List[str] = []
    reasons: List[str] = []
    log = logger or logging.getLogger(__name__)

    def record(message: str) -> None:
        logs.append(message)
        log.info(message)

    try:
        # 1. GPT5Master_personality.json must load (fail-fast on failure).
        personality = _load_json(personality_path)
        record("personality json loaded successfully")

        hard_constraint = personality["hard_constraint_enforcement"]
        evidence_policy = personality["decision_evidence_policy"]
        authority = personality["authority"]

        # 2. default_policy = No-Go enforced unless explicit approval.
        default_policy = hard_constraint["default_policy"]
        if default_policy != "No-Go":
            raise EnforcementError(
                "default_policy is not No-Go; enforcement requires No-Go"
            )
        if not explicit_approval:
            reasons.append("explicit approval is required to proceed")
            record("blocked: missing explicit approval")

        # 3. Decision Evidence required_fields must be complete.
        required_fields = evidence_policy["required_fields"]
        if decision_evidence is not None:
            missing = _validate_required_fields(decision_evidence, required_fields)
            if missing:
                reasons.append(f"decision evidence missing fields: {missing}")
                record("blocked: decision evidence missing required fields")

        # 4. Trigger detection => evidence required.
        triggers = evidence_policy["triggers"]
        trigger_hits = _detect_triggers(context_text, triggers)
        if trigger_hits and decision_evidence is None:
            reasons.append(
                f"decision evidence required due to triggers: {trigger_hits}"
            )
            record("blocked: triggers detected without evidence")
        if trigger_hits and decision_evidence is not None:
            missing = _validate_required_fields(decision_evidence, required_fields)
            if missing:
                reasons.append(f"decision evidence missing fields: {missing}")
                record("blocked: trigger evidence missing required fields")

        # 5. no_silent_fail = true => ensure logs recorded on failures.
        if authority.get("no_silent_fail") is True and reasons:
            record("no_silent_fail: enforcement failure recorded")

    except EnforcementError as exc:
        # Fail-fast and record exception.
        record(f"enforcement error: {exc}")
        if "authority" in locals() and authority.get("no_silent_fail") is True:
            record("no_silent_fail: exception recorded")
        return EnforcementResult(False, [str(exc)], logs)
    except Exception as exc:  # noqa: BLE001 - ensure logging for silent fail prevention
        record(f"unexpected error: {exc}")
        return EnforcementResult(False, [str(exc)], logs)

    allowed = not reasons
    return EnforcementResult(allowed, reasons, logs)


__all__ = [
    "EnforcementError",
    "EnforcementResult",
    "enforce_personality_gate",
]
