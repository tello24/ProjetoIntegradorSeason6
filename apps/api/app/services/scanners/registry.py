from dataclasses import dataclass
from pathlib import Path

from app.services.scanners.base import ScannerAdapter
from app.services.scanners.nessus import NessusAdapter


@dataclass(frozen=True, slots=True)
class ScannerSource:
    key: str
    display_name: str
    extensions: tuple[str, ...]


_ADAPTERS: tuple[ScannerAdapter, ...] = (NessusAdapter(),)


def list_scanner_sources() -> tuple[ScannerSource, ...]:
    return tuple(
        ScannerSource(
            key=adapter.key,
            display_name=adapter.display_name,
            extensions=adapter.extensions,
        )
        for adapter in _ADAPTERS
    )


def resolve_scanner_adapter(filename: str) -> ScannerAdapter | None:
    suffix = Path(filename).suffix.lower()
    return next(
        (adapter for adapter in _ADAPTERS if suffix in adapter.extensions),
        None,
    )


def get_scanner_adapter(key: str) -> ScannerAdapter:
    adapter = next((item for item in _ADAPTERS if item.key == key), None)
    if adapter is None:
        raise LookupError(f"Scanner não registrado: {key}")
    return adapter
