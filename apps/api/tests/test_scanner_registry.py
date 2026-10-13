from app.services.scanners.registry import (
    get_scanner_adapter,
    list_scanner_sources,
    resolve_scanner_adapter,
)


def test_registry_exposes_nessus_adapter() -> None:
    sources = list_scanner_sources()

    assert sources[0].key == "nessus"
    assert sources[0].extensions == (".nessus",)
    assert resolve_scanner_adapter("resultado.NESSUS") is get_scanner_adapter("nessus")


def test_registry_rejects_unknown_extension() -> None:
    assert resolve_scanner_adapter("resultado.xml") is None
