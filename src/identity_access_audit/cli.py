from __future__ import annotations

import argparse
import csv
import os
from typing import List

from .detect import detect_m365_file_type
from .mapping import build_m365_alias_map, build_m365_token_hints, resolve_field
from .models import MappingReport
from .reporting import print_mapping_report
from .rules import gate_rules, m365_rules_v01


def _read_csv_headers(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        row = next(reader, [])
        return [c.strip() for c in row if c is not None]


def _list_csv_files(path: str) -> List[str]:
    if os.path.isdir(path):
        out: List[str] = []
        for root, _, files in os.walk(path):
            for fn in files:
                if fn.lower().endswith(".csv"):
                    out.append(os.path.join(root, fn))
        return sorted(out)
    return [path]


def inspect_file(path: str, platform: str) -> int:
    headers = _read_csv_headers(path)

    if platform != "m365":
        print(f"Only --platform m365 supported in v0.1 (got {platform})")
        return 2

    det = detect_m365_file_type(headers)
    alias_map = build_m365_alias_map()
    token_hints = build_m365_token_hints()

    mapped_fields = []
    used_headers = set()

    canonicals = [
        "id",
        "upn",
        "email",
        "display_name",
        "account_enabled",
        "user_type",
        "last_signin_at",
        "mfa_state",
    ]

    for c in canonicals:
        fm = resolve_field(
            canonical=c,
            headers=headers,
            aliases=alias_map.get(c, []),
            canon_tokens=token_hints.get(c, []),
        )
        mapped_fields.append(fm)
        if fm.source_column:
            used_headers.add(fm.source_column)

    mapped_bool = {fm.canonical: (fm.source_column is not None) for fm in mapped_fields}
    mapped_bool["groups_or_roles"] = False  # reserved canonical, not mapped in v0.1

    runnable, skipped = gate_rules(m365_rules_v01(), mapped_bool)
    unmapped = [h for h in headers if h not in used_headers]

    rep = MappingReport(
        platform=platform,
        file_path=path,
        detection=det,
        header_count=len(headers),
        mapped=mapped_fields,
        unmapped_headers=unmapped,
        runnable_rules=runnable,
        skipped_rules=skipped,
        notes=[
            "Rules are gated strictly: if required fields are missing, the rule is skipped (no guessing).",
            "Next: add directory mode merge and groups/roles ingestion to unlock privilege-based rules.",
        ],
    )

    print_mapping_report(rep)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="identity-access-audit",
        description="Offline identity & access audit tool",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_inspect = sub.add_parser("inspect", help="Inspect CSV headers and generate a mapping report")
    p_inspect.add_argument("path", help="CSV file or directory containing CSV exports")
    p_inspect.add_argument("--platform", default="m365", choices=["m365"], help="Export source platform")

    p_audit = sub.add_parser("audit", help="Run audit rules (v0.1 stub)")
    p_audit.add_argument("path", help="CSV folder (exports)")
    p_audit.add_argument("--platform", default="m365", choices=["m365"])
    p_audit.add_argument("--since", default="90", help="Dormancy threshold in days (future)")
    p_audit.add_argument("--out", default="", help="Write report to file (future)")

    args = parser.parse_args()

    if args.cmd == "inspect":
        files = _list_csv_files(args.path)
        rc = 0
        for fp in files:
            rc = max(rc, inspect_file(fp, args.platform))
        raise SystemExit(rc)

    if args.cmd == "audit":
        print("audit: not implemented yet. Start with: identity-access-audit inspect <path>")
        raise SystemExit(0)


if __name__ == "__main__":
    main()
