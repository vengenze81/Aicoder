from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Pattern


@dataclass(slots=True)
class LogEntry:
    raw: str
    kind: str
    message: str = field(init=False)

    def __post_init__(self) -> None:
        self.message = self.raw
        prefix = self.kind.upper() + ":"
        if self.raw.startswith(prefix):
            self.message = self.raw[len(prefix) :].lstrip()


@dataclass(slots=True)
class ParsedLog:
    errors: List[LogEntry] = field(default_factory=list)
    warnings: List[LogEntry] = field(default_factory=list)
    infos: List[LogEntry] = field(default_factory=list)
    others: List[LogEntry] = field(default_factory=list)

    def all_entries(self) -> List[LogEntry]:
        return self.errors + self.warnings + self.infos + self.others


class LogParser:
    _PATTERNS: List[tuple[Pattern[str], str]] = [
        (re.compile(r"^\s*error[:\s]", re.IGNORECASE), "error"),
        (re.compile(r"^\s*warning[:\s]", re.IGNORECASE), "warning"),
        (re.compile(r"^\s*info[:\s]", re.IGNORECASE), "info"),
        (re.compile(r"^\s*debug[:\s]", re.IGNORECASE), "debug"),
    ]

    @classmethod
    def _classify(cls, line: str) -> str:
        for pattern, kind in cls._PATTERNS:
            if pattern.search(line):
                return kind
        return "other"

    @classmethod
    def parse(cls, source: Iterable[str]) -> ParsedLog:
        result = ParsedLog()
        for raw_line in source:
            line = raw_line.rstrip("\n")
            kind = cls._classify(line)
            entry = LogEntry(raw=line, kind=kind)
            if kind == "error":
                result.errors.append(entry)
            elif kind == "warning":
                result.warnings.append(entry)
            elif kind == "info":
                result.infos.append(entry)
            else:
                result.others.append(entry)
        return result