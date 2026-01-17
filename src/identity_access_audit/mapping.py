from __future__ import annotations

from typing import Dict, List, Tuple

from .models import FieldMapping


def normalize_header(h: str) -> str:
    s = "".join(ch.lower() if ch.isalnum() else " " for ch in h)
    return " ".join(s.split())


def header_tokens(h: str) -> List[str]:
    return normalize_header(h).split()


def token_overlap_score(canon_tokens: List[str], header_toks: List[str]) -> float:
    if not canon_tokens:
        return 0.0
    set_h = set(header_toks)
    hit = sum(1 for t in canon_tokens if t in set_h)
    return hit / len(canon_tokens)


def resolve_field(
    canonical: str,
    headers: List[str],
    aliases: List[str],
    canon_tokens: List[str],
) -> FieldMapping:
    norm_headers = {h: normalize_header(h) for h in headers}

    # 1) Alias exact match (strong)
    alias_norm = set(normalize_header(a) for a in aliases)
    alias_hits: List[Tuple[str, float]] = []
    for raw, nh in norm_headers.items():
        if nh in alias_norm:
            alias_hits.append((raw, 0.98))

    if alias_hits:
        alias_hits.sort(key=lambda x: (-x[1], len(x[0])))
        chosen, conf = alias_hits[0]
        return FieldMapping(
            canonical=canonical,
            source_column=chosen,
            confidence=conf,
            method="alias",
            candidates=alias_hits[:5],
        )

    # 2) Token overlap (medium)
    scored: List[Tuple[str, float]] = []
    for raw in headers:
        sc = token_overlap_score(canon_tokens, header_tokens(raw))
        if sc > 0:
            conf = 0.45 + 0.45 * sc  # 0.45..0.90
            scored.append((raw, conf))

    if scored:
        scored.sort(key=lambda x: (-x[1], len(x[0])))
        chosen, conf = scored[0]
        return FieldMapping(
            canonical=canonical,
            source_column=chosen,
            confidence=conf,
            method="token",
            candidates=scored[:5],
        )

    # 3) Not mapped
    return FieldMapping(
        canonical=canonical,
        source_column=None,
        confidence=0.0,
        method="none",
        candidates=[],
    )


def build_m365_alias_map() -> Dict[str, List[str]]:
    return {
        "id": ["id", "objectid", "object id", "userid", "user id"],
        "upn": ["userprincipalname", "user principal name", "upn"],
        "email": ["mail", "email", "email address", "primarysmtpaddress", "primary smtp address"],
        "display_name": ["displayname", "display name", "name", "user display name"],
        "account_enabled": ["accountenabled", "account enabled", "enabled", "isenabled", "block sign in", "blocked"],
        "user_type": ["usertype", "user type", "member", "guest"],
        "last_signin_at": ["lastsignindatetime", "last sign-in", "last signin", "lastsigninat"],
        "mfa_state": ["mfa", "mfa enabled", "mfastatus", "authentication requirement", "mfa required"],
    }


def build_m365_token_hints() -> Dict[str, List[str]]:
    return {
        "id": ["id", "object"],
        "upn": ["user", "principal", "name"],
        "email": ["mail", "email", "smtp"],
        "display_name": ["display", "name"],
        "account_enabled": ["account", "enabled"],
        "user_type": ["user", "type", "guest", "member"],
        "last_signin_at": ["last", "sign", "in"],
        "mfa_state": ["mfa", "authentication"],
    }
