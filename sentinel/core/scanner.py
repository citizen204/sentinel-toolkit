from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .finding import Finding

if TYPE_CHECKING:
    from .config import Config

_REGISTRY: dict[str, type["BaseScanner"]] = {}


class BaseScanner(ABC):
    name: str = ""

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
