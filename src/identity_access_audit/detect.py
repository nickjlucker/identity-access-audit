from __future__ import annotations

from typing import List, Set

from .models import FileDetection


def _norm(s: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else " " for ch in s).strip()


def _tokenize(headers: List[str]) -> Set[str]:
    toks: Set[str] = set()
    for h in headers:
        for t in _norm(h).split():
            if t:
                toks.add(t)
    return toks


def detect_m365_file_type(headers: List[str]) -> FileDetection:
    toks = _tokenize(headers)

    # Simple, explainable fingerprints.
    users_signals = [
        {"userprincipalname", "upn"},
        {"displayname", "name"},
        {"accountenabled", "enabled", "block"},
        {"usertype", "member", "guest"},
        {"mail", "email"},
    ]
    signin_signals = [
        {"ip", "address"},
        {"application", "app"},
        {"client"},
        {"conditional", "access"},
        {"status", "result"},
        {"createddatetime", "timegenerated", "date", "timestamp"},
    ]
    audit_signals = [
        {"activity", "operation"},
        {"initiated", "by"},
        {"target", "resources", "targetresources"},
        {"result", "status"},
        {"createddatetime", "timegenerated", "date", "timestamp"},
    ]

    def score(signals: List[Set[str]]) -> int:
        hit = 0
        for group in signals:
            if any(t in toks for t in group):
                hit += 1
        return hit

    users_hit = score(users_signals)
    signin_hit = score(signin_signals)
    audit_hit = score(audit_signals)

    scores = {
        "users": users_hit,
        "signin_logs": signin_hit,
        "audit_logs": audit_hit,
    }
    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]

    reasons: List[str] = [f"token_hits={scores}"]

    # Confidence heuristic: 0..1 based on hit counts.
    max_possible = 6
    confidence = min(1.0, best_score / max_possible)

    if best_score <= 1:
        return FileDetection(
            file_type="unknown",
            confidence=0.2,
            reasons=reasons + ["insufficient fingerprint hits"],
        )

    return FileDetection(file_type=best_type, confidence=confidence, reasons=reasons)
