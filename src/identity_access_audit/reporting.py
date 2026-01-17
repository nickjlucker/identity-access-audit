from __future__ import annotations

from .models import MappingReport


def print_mapping_report(rep: MappingReport) -> None:
    det = rep.detection
    print("\n=== Identity Access Audit: Inspect ===")
    print(f"Platform: {rep.platform}")
    print(f"File:     {rep.file_path}")
    print(f"Type:     {det.file_type}  (confidence={det.confidence:.2f})")
    if det.reasons:
        for r in det.reasons[:3]:
            print(f"  - {r}")

    print("\n-- Field Mapping --")
    for fm in rep.mapped:
        if fm.source_column:
            print(f"  {fm.canonical:16} <- {fm.source_column}  [{fm.method}, {fm.confidence:.2f}]")
        else:
            print(f"  {fm.canonical:16} <- (missing)")

    if rep.unmapped_headers:
        print("\n-- Unmapped Headers (sample) --")
        for h in rep.unmapped_headers[:12]:
            print(f"  - {h}")
        if len(rep.unmapped_headers) > 12:
            print(f"  ... (+{len(rep.unmapped_headers)-12} more)")

    print("\n-- Rule Readiness --")
    if rep.runnable_rules:
        print("Runnable:")
        for rid in rep.runnable_rules:
            print(f"  - {rid}")
    else:
        print("Runnable: (none)")

    if rep.skipped_rules:
        print("\nSkipped:")
        for rid, reason in rep.skipped_rules:
            print(f"  - {rid}: {reason}")

    if rep.notes:
        print("\n-- Notes --")
        for n in rep.notes:
            print(f"  - {n}")
    print("")
