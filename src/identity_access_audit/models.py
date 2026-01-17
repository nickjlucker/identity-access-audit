from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class FileDetection:
    file_type: str  # users | signin_logs | audit_logs | unknown
    confidence: float
    reasons: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class FieldMapping:
    canonical: str
    source_column: Optional[str]  # None if not mapped
    confidence: float
    method: str  # alias | token | none
    candidates: List[Tuple[str, float]] = field(default_factory=list)


@dataclass(frozen=True)
class MappingReport:
    platform: str
    file_path: str
    detection: FileDetection
    header_count: int
    mapped: List[FieldMapping]
    unmapped_headers: List[str]
    runnable_rules: List[str]
    skipped_rules: List[Tuple[str, str]]  # (rule_id, reason)
    notes: List[str] = field(default_factory=list)
