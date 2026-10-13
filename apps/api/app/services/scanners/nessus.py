from pathlib import Path

from app.services.nessus.parser import NessusParser
from app.services.scanners.models import ScanParseResult


class NessusAdapter:
    key = "nessus"
    display_name = "Tenable Nessus"
    extensions = (".nessus",)

    def parse(self, file_path: str | Path) -> ScanParseResult:
        return NessusParser().parse(file_path)
