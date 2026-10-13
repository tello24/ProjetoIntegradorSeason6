from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ScanHost:
    address: str
    fqdn: str | None = None
    netbios: str | None = None
    operating_system: str | None = None
    mac_address: str | None = None
    system_type: str | None = None
    credentialed: bool = False
    bios_uuid: str | None = None
    cpes: tuple[str, ...] = ()
    operating_system_confidence: int | None = None
    operating_system_method: str | None = None
    local_checks_protocol: str | None = None
    scan_started_at: datetime | None = None
    scan_ended_at: datetime | None = None
    last_authenticated_results_at: datetime | None = None
    last_unauthenticated_results_at: datetime | None = None
    patch_summary_total_cves: int | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanService:
    host_address: str
    protocol: str
    port: int
    service: str | None = None


@dataclass(frozen=True, slots=True)
class ScanFinding:
    host_address: str
    plugin_id: int
    plugin_name: str
    plugin_family: str | None
    protocol: str
    port: int
    service: str | None
    severity: int
    risk_factor: str | None
    cvss2: float | None
    cvss3: float | None
    cvss4: float | None
    cvss3_vector: str | None
    vpr: float | None
    epss: float | None
    exploitable: bool
    exploit_maturity: str | None
    synopsis: str | None
    description: str | None
    solution: str | None
    plugin_output: str | None
    cves: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanParseResult:
    report_name: str
    policy_name: str | None
    hosts: tuple[ScanHost, ...]
    findings: tuple[ScanFinding, ...]
    services: tuple[ScanService, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def relevant_findings(self) -> int:
        return sum(finding.severity > 0 for finding in self.findings)
