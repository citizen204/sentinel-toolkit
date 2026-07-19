from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .finding import Finding

if TYPE_CHECKING:
    from .config import Config

_REGISTRY: dict[str, type["BaseScanner"]] = {}


class ScannerSkipped(Exception):
    """Raised when a scanner has nothing to assess: no target, no such file.

    This exists because returning ``[]`` is indistinguishable from "assessed and
    found nothing". A misspelled log path would produce an empty, green-looking
    report for a host nobody actually looked at. Skipping is reported, not hidden.
    """

    def __init__(self, reason: str, remediation: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.remediation = remediation


class BaseScanner(ABC):
    name: str = ""

    def __init__(self) -> None:
        # Scopes this run actually reached, recorded during execution. A scanner
        # that enumerates accounts or regions appends a CoverageUnit per scope it
        # attempted; leaving this empty means "nothing proven", so the diff will
        # not retire this scanner's earlier findings.
        self.coverage_units: list = []

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "name", ""):
            _REGISTRY[cls.name] = cls

    @abstractmethod
    def run(self, config: "Config") -> list[Finding]:
        ...


def get_scanner(name: str) -> type[BaseScanner]:
    return _REGISTRY[name]


def all_scanners() -> dict[str, type[BaseScanner]]:
    return dict(_REGISTRY)
