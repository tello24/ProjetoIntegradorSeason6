from pathlib import Path
from typing import Protocol

from app.services.scanners.models import ScanParseResult


class ScanParseError(ValueError):
    """Raised when an uploaded scanner export cannot be normalized safely."""


class ScannerAdapter(Protocol):
    key: str
    display_name: str
    extensions: tuple[str, ...]

    def parse(self, file_path: str | Path) -> ScanParseResult: ...
