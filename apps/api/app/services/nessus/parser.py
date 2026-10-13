from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from app.services.nessus.models import NessusFinding, NessusHost, NessusParseResult
from app.services.scanners.base import ScanParseError
from app.services.scanners.models import ScanService


class NessusParseError(ScanParseError):
    """Raised when an upload is not a valid Nessus v2 export."""


class NessusParser:
    """Streaming parser for `NessusClientData_v2` exports.

    The parser keeps only the normalized result in memory and clears each host XML
    element as soon as it has been processed.
    """

    def __init__(self, *, include_informational: bool = False) -> None:
        self.include_informational = include_informational

    def parse(self, file_path: str | Path) -> NessusParseResult:
        path = Path(file_path)
        if not path.is_file():
            raise NessusParseError("Arquivo de scan não encontrado.")

        report_name: str | None = None
        policy_name: str | None = None
        root_checked = False
        hosts: list[NessusHost] = []
        findings: list[NessusFinding] = []
        services: list[ScanService] = []
        seen_findings: set[tuple[str, int, str, int]] = set()
        warnings: list[str] = []

        try:
            context = ElementTree.iterparse(path, events=("start", "end"))
            for event, element in context:
                if event == "start" and not root_checked:
                    root_checked = True
                    if element.tag != "NessusClientData_v2":
                        raise NessusParseError("O arquivo não é uma exportação Nessus v2.")

                if event != "end":
                    continue

                if element.tag == "policyName" and policy_name is None:
                    policy_name = _clean_text(element.text)
                elif element.tag == "Report" and report_name is None:
                    report_name = element.attrib.get("name")
                elif element.tag == "ReportHost":
                    host, host_findings, host_services = self._parse_host(element)
                    hosts.append(host)
                    services.extend(host_services)
                    for finding in host_findings:
                        key = (
                            finding.host_address,
                            finding.plugin_id,
                            finding.protocol,
                            finding.port,
                        )
                        if key in seen_findings:
                            continue
                        seen_findings.add(key)
                        findings.append(finding)
                    element.clear()
        except NessusParseError:
            raise
        except ElementTree.ParseError as exc:
            raise NessusParseError("XML inválido ou corrompido.") from exc
        except (OSError, ValueError) as exc:
            raise NessusParseError("Não foi possível processar o arquivo de scan.") from exc

        if not root_checked or not report_name:
            raise NessusParseError("O arquivo não contém um relatório Nessus válido.")
        if not hosts:
            warnings.append("O relatório não contém ativos.")

        return NessusParseResult(
            report_name=report_name,
            policy_name=policy_name,
            hosts=tuple(hosts),
            findings=tuple(findings),
            services=tuple(services),
            warnings=tuple(warnings),
        )

    def _parse_host(
        self,
        element: Element,
    ) -> tuple[NessusHost, Iterable[NessusFinding], Iterable[ScanService]]:
        properties = {
            tag.attrib.get("name", ""): _clean_text(tag.text)
            for tag in element.findall("./HostProperties/tag")
        }
        fallback_name = element.attrib.get("name", "").strip()
        address = properties.get("host-ip") or fallback_name
        if not address:
            raise NessusParseError("Foi encontrado um ativo sem endereço.")

        cpes = tuple(
            sorted(
                {
                    value
                    for key, value in properties.items()
                    if (key == "cpe" or key.startswith("cpe-")) and value
                }
            )[:64]
        )
        metadata = {
            key: value
            for key, value in {
                "policy_used": properties.get("policy-used"),
            }.items()
            if value
        }

        host = NessusHost(
            address=address,
            fqdn=properties.get("host-fqdn"),
            netbios=properties.get("netbios-name"),
            operating_system=properties.get("operating-system"),
            mac_address=properties.get("mac-address"),
            system_type=properties.get("system-type"),
            credentialed=_to_bool(properties.get("Credentialed_Scan")),
            bios_uuid=properties.get("bios-uuid"),
            cpes=cpes,
            operating_system_confidence=_to_optional_int(
                properties.get("operating-system-conf"),
                minimum=-1,
                maximum=100,
            ),
            operating_system_method=properties.get("operating-system-method"),
            local_checks_protocol=properties.get("local-checks-proto"),
            scan_started_at=_to_timestamp(
                properties.get("HOST_START_TIMESTAMP"),
                fallback=properties.get("HOST_START"),
            ),
            scan_ended_at=_to_timestamp(
                properties.get("HOST_END_TIMESTAMP"),
                fallback=properties.get("HOST_END"),
            ),
            last_authenticated_results_at=_to_timestamp(
                properties.get("LastAuthenticatedResults")
            ),
            last_unauthenticated_results_at=_to_timestamp(
                properties.get("LastUnauthenticatedResults")
            ),
            patch_summary_total_cves=_to_optional_int(
                properties.get("patch-summary-total-cves"),
                minimum=0,
            ),
            metadata=metadata,
        )

        findings: list[NessusFinding] = []
        service_map: dict[tuple[str, int], ScanService] = {}
        for item in element.findall("./ReportItem"):
            protocol = item.attrib.get("protocol", "tcp").strip().lower()
            port = _to_int(item.attrib.get("port"), default=0)
            service = _optional_attribute(item, "svc_name")
            if 0 < port <= 65535:
                key = (protocol, port)
                previous = service_map.get(key)
                service_map[key] = ScanService(
                    host_address=address,
                    protocol=protocol,
                    port=port,
                    service=service or (previous.service if previous else None),
                )

            severity = _to_int(item.attrib.get("severity"), default=0)
            if severity == 0 and not self.include_informational:
                continue

            plugin_id = _to_int(item.attrib.get("pluginID"), default=-1)
            if plugin_id < 0:
                continue

            findings.append(
                NessusFinding(
                    host_address=address,
                    plugin_id=plugin_id,
                    plugin_name=item.attrib.get("pluginName", "Plugin sem nome").strip(),
                    plugin_family=_optional_attribute(item, "pluginFamily"),
                    protocol=protocol,
                    port=port,
                    service=service,
                    severity=severity,
                    risk_factor=_child_text(item, "risk_factor"),
                    cvss2=_to_float(_child_text(item, "cvss_base_score")),
                    cvss3=_to_float(_child_text(item, "cvss3_base_score")),
                    cvss4=_to_float(_child_text(item, "cvss4_base_score")),
                    cvss3_vector=_child_text(item, "cvss3_vector"),
                    vpr=_to_float(_child_text(item, "vpr_score")),
                    epss=_to_float(_child_text(item, "epss_score")),
                    exploitable=_to_bool(_child_text(item, "exploit_available")),
                    exploit_maturity=_child_text(item, "exploitability_ease"),
                    synopsis=_child_text(item, "synopsis"),
                    description=_child_text(item, "description"),
                    solution=_child_text(item, "solution"),
                    plugin_output=_child_text(item, "plugin_output"),
                    cves=tuple(
                        sorted(
                            {
                                cve
                                for node in item.findall("./cve")
                                if (cve := _clean_text(node.text))
                            }
                        )
                    ),
                    references=_child_references(item),
                )
            )

        return host, findings, sorted(
            service_map.values(),
            key=lambda service: (service.protocol, service.port),
        )


def _child_text(element: Element, child_name: str) -> str | None:
    child = element.find(f"./{child_name}")
    return _clean_text(child.text) if child is not None else None


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _optional_attribute(element: Element, attribute: str) -> str | None:
    return _clean_text(element.attrib.get(attribute))


def _split_references(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(
        reference
        for line in value.splitlines()
        if (reference := line.strip()).startswith(("https://", "http://"))
    )


def _child_references(element: Element) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            reference
            for child in element.findall("./see_also")
            for reference in _split_references(_clean_text(child.text))
        )
    )


def _to_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "sim"}


def _to_int(value: str | None, *, default: int) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _to_optional_int(
    value: str | None,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and parsed < minimum:
        return None
    if maximum is not None and parsed > maximum:
        return None
    return parsed


def _to_timestamp(value: str | None, *, fallback: str | None = None) -> datetime | None:
    if value:
        try:
            return datetime.fromtimestamp(int(value), tz=UTC)
        except (OverflowError, TypeError, ValueError):
            pass
    if fallback:
        try:
            return datetime.strptime(fallback, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
