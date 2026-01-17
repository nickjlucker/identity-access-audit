from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    title: str
    required_fields: List[str]


def m365_rules_v01() -> List[RuleSpec]:
    # NOTE: These are readiness specs only (evaluate comes later).
    return [
        RuleSpec("IAM001", "Privileged accounts present", required_fields=["groups_or_roles"]),
        RuleSpec("IAM002", "Dormant enabled users", required_fields=["last_signin_at", "account_enabled"]),
        RuleSpec("IAM003", "MFA explicitly disabled", required_fields=["mfa_state"]),
        RuleSpec("IAM004", "Guest user with elevated access", required_fields=["user_type", "groups_or_roles"]),
        RuleSpec("IAM005", "Toxic overlap: admin + finance-ish", required_fields=["groups_or_roles"]),
    ]


def gate_rules(
    rules: List[RuleSpec],
    mapped_fields: Dict[str, bool],
) -> Tuple[List[str], List[Tuple[str, str]]]:
    runnable: List[str] = []
    skipped: List[Tuple[str, str]] = []

    for r in rules:
        missing = [f for f in r.required_fields if not mapped_fields.get(f, False)]
        if missing:
            skipped.append((r.rule_id, f"missing required field(s): {', '.join(missing)}"))
        else:
            runnable.append(r.rule_id)

    return runnable, skipped
