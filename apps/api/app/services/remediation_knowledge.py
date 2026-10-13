import re
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

KNOWLEDGE_VERSION = "2026-09-04"

_TRUSTED_REFERENCE_HOSTS = frozenset(
    {
        "access.redhat.com",
        "bugzilla.redhat.com",
        "docs.redhat.com",
        "docs.rockylinux.org",
        "errata.rockylinux.org",
        "git.kernel.org",
        "nvd.nist.gov",
        "security.access.redhat.com",
        "www.tenable.com",
    }
)
_TRUSTED_REFERENCE_DOMAINS = frozenset(
    {
        "apache.org",
        "apple.com",
        "broadcom.com",
        "canonical.com",
        "cisco.com",
        "debian.org",
        "fedoraproject.org",
        "fortinet.com",
        "grafana.com",
        "ibm.com",
        "kernel.org",
        "microsoft.com",
        "mitre.org",
        "mozilla.org",
        "nginx.org",
        "nist.gov",
        "oracle.com",
        "redhat.com",
        "rockylinux.org",
        "suse.com",
        "tenable.com",
        "ubuntu.com",
        "vmware.com",
    }
)
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_ADVISORY_PATTERN = re.compile(r"\b(RLSA|RHSA)-(\d{4}):(\d+)\b", re.IGNORECASE)
_RUNNING_KERNEL_PATTERN = re.compile(
    r"current running kernel level is\s+([^\s.]+(?:\.[^\s.]+)*)\.?",
    re.IGNORECASE,
)
_INSTALLED_PACKAGE_PATTERN = re.compile(
    r"Installed package\s+(.+?)\s+is greater than\s+(.+?)\.",
    re.IGNORECASE,
)

_RHEL_KERNEL_GUIDE = (
    "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/"
    "html/managing_monitoring_and_updating_the_kernel/"
    "assembly_the-linux-kernel_managing-monitoring-and-updating-the-kernel"
)
_RHEL_DNF_GUIDE = (
    "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/"
    "html/managing_software_with_the_dnf_tool/"
    "assembly_updating-rhel-9-content_managing-software-with-the-dnf-tool"
)
_ROCKY_ERRATA_GUIDE = "https://docs.rockylinux.org/latest/teams/rel_eng/errata/"
_GRAFANA_SECURITY_ADVISORIES = "https://grafana.com/security/security-advisories/"
_GRAFANA_UPGRADE_GUIDE = "https://grafana.com/docs/grafana/latest/upgrade-guide/"
_NIST_TLS_GUIDE = "https://csrc.nist.gov/pubs/sp/800/52/r2/final"


def build_official_references(
    *,
    plugin_id: int,
    title: str,
    cves: Iterable[str],
    scanner_references: Iterable[str],
    operating_system: str | None,
    family: str | None,
) -> list[str]:
    candidates: list[str] = []

    advisory = _ADVISORY_PATTERN.search(title)
    if advisory:
        prefix, year, identifier = advisory.groups()
        if prefix.upper() == "RLSA":
            candidates.append(f"https://errata.rockylinux.org/RLSA-{year}:{identifier}")
        else:
            candidates.append(f"https://access.redhat.com/errata/RHSA-{year}:{identifier}")

    if _is_grafana(title, family):
        candidates.extend(
            f"https://grafana.com/security/security-advisories/{cve.lower()}/"
            for cve in cves
            if _CVE_PATTERN.fullmatch(cve.strip())
        )
        candidates.extend((_GRAFANA_SECURITY_ADVISORIES, _GRAFANA_UPGRADE_GUIDE))

    if plugin_id > 0:
        candidates.append(f"https://www.tenable.com/plugins/nessus/{plugin_id}")

    if _is_enterprise_linux_kernel(title, family, operating_system):
        candidates.extend((_RHEL_KERNEL_GUIDE, _RHEL_DNF_GUIDE, _ROCKY_ERRATA_GUIDE))

    if _is_tls_or_ssh(title, family):
        candidates.append(_NIST_TLS_GUIDE)

    for cve in cves:
        normalized_cve = cve.upper().strip()
        if _CVE_PATTERN.fullmatch(normalized_cve):
            candidates.append(f"https://nvd.nist.gov/vuln/detail/{normalized_cve}")

    candidates.extend(scanner_references)
    return _deduplicated_trusted_urls(candidates, limit=30)


def build_trusted_guidance(
    *,
    title: str,
    family: str | None,
    operating_system: str | None,
    description: str | None,
    scanner_evidence: str | None,
    cvss3_vector: str | None,
    credentialed_scan: bool,
) -> tuple[list[str], list[str]]:
    rules = [
        "Trate a evidência específica do plugin como mais importante que a solução genérica.",
        "Não transforme possibilidade em certeza e não afirme exploração bem-sucedida sem "
        "evidência.",
        "Não classifique uma falha como execução remota de código (RCE) sem evidência explícita; "
        "AV:N sozinho indica alcance pela rede, não execução de código.",
        "Separe fatos observados de hipóteses e coloque todo contexto ausente em assumptions.",
        "Não invente versões, espaço mínimo, caminhos, serviços, comandos ou recursos do ambiente.",
        "Prefira comandos de consulta antes de comandos de mudança e condicione cada ação ao "
        "resultado.",
        "Nunca recomende exploração; produza somente orientação defensiva para revisão humana.",
    ]
    facts = _derive_facts(description, scanner_evidence, cvss3_vector)

    if not credentialed_scan:
        rules.append(
            "O scan não está marcado como credenciado: confirme localmente produto, versão e "
            "configuração antes de indicar qualquer comando de correção."
        )

    if _is_enterprise_linux_kernel(title, family, operating_system):
        rules.extend(
            [
                "Em Enterprise Linux 9, dnf update kernel instala o novo kernel e dependências; "
                "um reboot é necessário para começar a executá-lo.",
                "Antes de atualizar, compare uname -r, os pacotes kernel instalados e o kernel "
                "padrão informado por grubby --default-kernel.",
                "Se a evidência mostrar pacote corrigido instalado e kernel antigo em execução, "
                "não reinstale por padrão: trate como reboot pendente.",
                "Não use download de RPM como prova de compatibilidade e não exija um valor fixo "
                "de espaço em disco; valide a transação e o espaço real do sistema.",
                "No rollback, inicialize primeiro um kernel anterior conhecido e use grubby para "
                "selecioná-lo; não remova com rpm -e o kernel em execução.",
                "Valide aplicações e endpoints aprovados do ambiente; não dependa de ping para um "
                "IP público como teste universal.",
            ]
        )

    if is_enterprise_linux_kernel_reboot_pending(
        title=title,
        family=family,
        operating_system=operating_system,
        scanner_evidence=scanner_evidence,
    ):
        rules.insert(
            0,
            "DECISÃO DETERMINÍSTICA: a evidência informa reboot pendente. Se os pacotes instalados "
            "já forem iguais ou superiores à versão corrigida, a execução deve priorizar janela, "
            "reboot, validação do kernel carregado e novo scan, sem reinstalação automática.",
        )

    if _is_grafana(title, family):
        rules.extend(
            [
                "Para Grafana autogerenciado, confirme edição, versão exata e método de instalação "
                "(pacote, contêiner ou binário) antes de escolher o procedimento.",
                "Use a versão corrigida indicada pelo advisory oficial para a linha instalada; não "
                "presuma que migrar para a versão principal mais nova é a única correção.",
                "Antes do upgrade, preserve banco, configuração e dados de plugins e consulte o "
                "guia e o changelog da versão de destino.",
                "Valide autenticação, dashboards, datasources, alertas, plugins, API e saúde da "
                "instância em homologação e depois em produção.",
                "O rollback depende do método de instalação e de possíveis migrações de banco; "
                "não prometa downgrade sem backup restaurável testado.",
            ]
        )

    if _is_tls_or_ssh(title, family):
        rules.extend(
            [
                "Identifique onde a conexão termina (aplicação, proxy, balanceador ou appliance) "
                "antes de alterar TLS, certificado ou SSH.",
                "Para mudanças de protocolo, cifra ou algoritmo, inventarie clientes dependentes e "
                "teste compatibilidade antes de desabilitar opções antigas.",
                "Em SSH, preserve acesso fora de banda e valide uma nova sessão antes de encerrar "
                "a sessão administrativa atual.",
                "Em certificados, valide cadeia, emissor, SAN, validade e trust store; nunca "
                "corrija falha de confiança desabilitando a verificação do cliente.",
            ]
        )

    return rules, facts


def is_enterprise_linux_kernel_reboot_pending(
    *,
    title: str,
    family: str | None,
    operating_system: str | None,
    scanner_evidence: str | None,
) -> bool:
    evidence = scanner_evidence or ""
    return (
        _is_enterprise_linux_kernel(title, family, operating_system)
        and bool(_INSTALLED_PACKAGE_PATTERN.search(evidence))
        and "requires a reboot" in evidence.lower()
    )


def _derive_facts(
    description: str | None,
    scanner_evidence: str | None,
    cvss3_vector: str | None,
) -> list[str]:
    facts: list[str] = []
    evidence = scanner_evidence or ""

    package_matches = _INSTALLED_PACKAGE_PATTERN.findall(evidence)
    if package_matches:
        facts.append(
            f"O Nessus comparou {len(package_matches)} pacote(s) instalado(s) com a versão de "
            "correção e informou que os instalados são superiores."
        )

    running_kernel = _RUNNING_KERNEL_PATTERN.search(evidence)
    if running_kernel:
        facts.append(
            f"O kernel informado como atualmente em execução é {running_kernel.group(1)}."
        )

    if "requires a reboot" in evidence.lower():
        facts.append("O plugin declarou explicitamente que o sistema precisa de reboot.")

    if description and "has not tested for these issues" in description.lower():
        facts.append(
            "O próprio plugin informa que não explorou as falhas e se baseou nas versões "
            "reportadas pelo sistema."
        )

    normalized_vector = (cvss3_vector or "").upper()
    if "/AV:L" in normalized_vector:
        facts.append("O vetor CVSS registrado indica vetor de ataque local (AV:L).")
    elif "/AV:N" in normalized_vector:
        facts.append("O vetor CVSS registrado indica vetor de ataque pela rede (AV:N).")

    return facts


def _is_enterprise_linux_kernel(
    title: str,
    family: str | None,
    operating_system: str | None,
) -> bool:
    haystack = " ".join(filter(None, (title, family, operating_system))).lower()
    return "kernel" in haystack and any(
        marker in haystack for marker in ("rocky", "red hat", "rhel", "enterprise linux")
    )


def _is_grafana(title: str, family: str | None) -> bool:
    return "grafana" in " ".join(filter(None, (title, family))).lower()


def _is_tls_or_ssh(title: str, family: str | None) -> bool:
    haystack = " ".join(filter(None, (title, family))).lower()
    return any(marker in haystack for marker in ("certificate", "cipher", "ssh", "ssl", "tls"))


def _deduplicated_trusted_urls(candidates: Iterable[str], *, limit: int) -> list[str]:
    trusted: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = _trusted_url(candidate)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        trusted.append(normalized)
        if len(trusted) >= limit:
            break
    return trusted


def _trusted_url(candidate: str) -> str | None:
    value = candidate.strip().rstrip(".,;)")
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not _is_trusted_reference_host(hostname)
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        return None
    return urlunsplit(("https", hostname, parsed.path or "/", "", ""))


def _is_trusted_reference_host(hostname: str) -> bool:
    return hostname in _TRUSTED_REFERENCE_HOSTS or any(
        hostname == domain or hostname.endswith(f".{domain}")
        for domain in _TRUSTED_REFERENCE_DOMAINS
    )
