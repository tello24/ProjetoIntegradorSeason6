from app.services.scanners.models import ScanFinding, ScanHost, ScanParseResult

# Aliases preserve the public Nessus parser API while its output now follows the
# normalized contract shared by every scanner adapter.
NessusHost = ScanHost
NessusFinding = ScanFinding
NessusParseResult = ScanParseResult

__all__ = ["NessusFinding", "NessusHost", "NessusParseResult"]
