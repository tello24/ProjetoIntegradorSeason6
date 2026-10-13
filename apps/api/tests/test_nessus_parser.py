from pathlib import Path

import pytest

from app.services.nessus import NessusParseError, NessusParser

VALID_NESSUS = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Policy><policyName>Teste seguro</policyName></Policy>
  <Report name="Ambiente acadêmico">
    <ReportHost name="192.0.2.10">
      <HostProperties>
        <tag name="host-ip">192.0.2.10</tag>
        <tag name="host-fqdn">host.exemplo.local</tag>
        <tag name="Credentialed_Scan">true</tag>
        <tag name="bios-uuid">00000000-0000-0000-0000-000000000001</tag>
        <tag name="system-type">general-purpose</tag>
        <tag name="operating-system">Example Linux 1</tag>
        <tag name="operating-system-conf">95</tag>
        <tag name="operating-system-method">SSH</tag>
        <tag name="local-checks-proto">ssh</tag>
        <tag name="HOST_START_TIMESTAMP">1893456000</tag>
        <tag name="HOST_END_TIMESTAMP">1893456065</tag>
        <tag name="LastAuthenticatedResults">1893456065</tag>
        <tag name="patch-summary-total-cves">4</tag>
        <tag name="policy-used">Política acadêmica</tag>
        <tag name="cpe-0">cpe:/o:example:linux:1</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="3"
        pluginID="10001" pluginName="Exemplo controlado" pluginFamily="General">
        <risk_factor>High</risk_factor>
        <cvss3_base_score>8.1</cvss3_base_score>
        <plugin_output>Installed package is current. This system requires a reboot.</plugin_output>
        <synopsis>Resumo de teste.</synopsis>
        <solution>Aplicar atualização de teste.</solution>
        <see_also>https://www.tenable.com/plugins/nessus/10001
https://nvd.nist.gov/vuln/detail/CVE-2099-0001</see_also>
        <cve>CVE-2099-0001</cve>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0"
        pluginID="10002" pluginName="Informativo" pluginFamily="General" />
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0"
        pluginID="10003" pluginName="Serviço observado" pluginFamily="General" />
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_parses_relevant_findings_and_host_snapshot(tmp_path: Path) -> None:
    scan_file = tmp_path / "sample.xml"
    scan_file.write_text(VALID_NESSUS, encoding="utf-8")

    result = NessusParser().parse(scan_file)

    assert result.report_name == "Ambiente acadêmico"
    assert result.policy_name == "Teste seguro"
    assert len(result.hosts) == 1
    assert result.hosts[0].credentialed is True
    assert result.hosts[0].bios_uuid == "00000000-0000-0000-0000-000000000001"
    assert result.hosts[0].cpes == ("cpe:/o:example:linux:1",)
    assert result.hosts[0].operating_system_confidence == 95
    assert result.hosts[0].operating_system_method == "SSH"
    assert result.hosts[0].local_checks_protocol == "ssh"
    assert result.hosts[0].scan_started_at is not None
    assert result.hosts[0].scan_ended_at is not None
    assert result.hosts[0].patch_summary_total_cves == 4
    assert result.hosts[0].metadata == {"policy_used": "Política acadêmica"}
    assert len(result.findings) == 1
    assert [(service.port, service.service) for service in result.services] == [
        (22, "ssh"),
        (443, "https"),
    ]
    assert result.findings[0].plugin_id == 10001
    assert result.findings[0].cves == ("CVE-2099-0001",)
    assert "requires a reboot" in (result.findings[0].plugin_output or "")
    assert result.findings[0].references == (
        "https://www.tenable.com/plugins/nessus/10001",
        "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
    )


def test_rejects_non_nessus_xml(tmp_path: Path) -> None:
    scan_file = tmp_path / "invalid.xml"
    scan_file.write_text("<not-nessus />", encoding="utf-8")

    with pytest.raises(NessusParseError, match="Nessus v2"):
        NessusParser().parse(scan_file)
