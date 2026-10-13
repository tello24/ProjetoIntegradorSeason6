import json
from decimal import Decimal

import pytest

from app.core.config import AIProviderConfig
from app.services import remediation
from app.services.remediation import (
    RemediationContext,
    generate_remediation_plan,
    remediation_input_signature,
)
from app.services.remediation_knowledge import build_official_references


def remediation_context() -> RemediationContext:
    return RemediationContext(
        plugin_id=10001,
        title="Synthetic critical finding",
        family="General",
        operating_system="Synthetic Linux",
        credentialed_scan=True,
        severity="critical",
        risk_factor="Critical",
        cves=["CVE-2099-0001"],
        synopsis="Synthetic test finding.",
        description="Used only by the automated test.",
        scanner_solution="Apply the synthetic test fix.",
        scanner_evidence=None,
        scanner_references=[],
        protocol="tcp",
        port=443,
        service="https",
        cvss=9.8,
        cvss3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vpr=9.0,
        epss=0.8,
        exploitable=True,
        exploit_maturity="Functional",
        neo_score=64,
        priority="prioritize",
    )


def provider_config(provider: str) -> AIProviderConfig:
    return AIProviderConfig(
        provider=provider,  # type: ignore[arg-type]
        api_key="test-key",
        model="claude-haiku-4-5" if provider == "anthropic" else "gpt-5.4-mini",
        timeout_seconds=10,
        max_output_tokens=2200,
        prompt_version="test-v1",
        input_price_per_million_usd=Decimal("1.00"),
        output_price_per_million_usd=Decimal("5.00"),
        workspace_id="wrkspc_test" if provider == "anthropic" else None,
    )


def draft_payload() -> dict[str, object]:
    return {
        "why_it_matters": "Explicação clara do impacto.",
        "summary": "Resumo seguro.",
        "priority_rationale": "Prioridade validada pelo NeoScore.",
        "prerequisites": ["Confirmar janela."],
        "steps": ["Aplicar correção validada."],
        "validation_steps": ["Executar novo scan."],
        "rollback_plan": ["Restaurar estado anterior."],
        "cautions": ["Revisar antes de executar."],
        "estimated_effort": "A estimar.",
        "assumptions": ["Confirmar a versão instalada."],
    }


@pytest.mark.asyncio
async def test_without_provider_returns_an_honest_scanner_template() -> None:
    plan = await generate_remediation_plan(remediation_context(), config=None)

    assert plan.source == "scanner_template"
    assert plan.model is None
    assert "Apply the synthetic test fix." in plan.steps
    assert any("novo scan" in step for step in plan.validation_steps)
    assert plan.warning is None
    assert plan.total_tokens is None


@pytest.mark.asyncio
async def test_openai_request_redacts_data_and_records_usage(monkeypatch) -> None:
    captured: dict[str, object] = {}
    context = remediation_context().model_copy(
        update={
            "description": (
                "Observed on 10.20.30.40, api.internal and https://private.example.com/finding."
            ),
            "scanner_evidence": "Asset 10.30.40.50 reported by scanner.private.internal.",
        }
    )

    def fake_post(payload, api_key, timeout_seconds):
        captured.update(payload)
        assert api_key == "test-key"
        assert timeout_seconds == 10
        return {
            "output_text": json.dumps(draft_payload()),
            "usage": {"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500},
        }

    monkeypatch.setattr(remediation, "_post_openai_payload", fake_post)
    plan = await generate_remediation_plan(context, config=provider_config("openai"))

    external_payload = json.dumps(captured)
    assert plan.source == "openai"
    assert plan.why_it_matters == "Explicação clara do impacto."
    assert "10.20.30.40" not in external_payload
    assert "api.internal" not in external_payload
    assert "private.example.com" not in external_payload
    assert "10.30.40.50" not in external_payload
    assert "scanner.private.internal" not in external_payload
    assert "[DADO_RESTRITO]" in external_payload
    assert captured["store"] is False
    assert plan.total_tokens == 1500
    assert plan.estimated_cost_usd == 0.0035
    assert plan.evidence_summary
    assert "https://www.tenable.com/plugins/nessus/10001" in plan.official_references


@pytest.mark.asyncio
async def test_anthropic_request_uses_native_structured_output(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(payload, api_key, workspace_id, timeout_seconds):
        captured.update(payload)
        assert api_key == "test-key"
        assert workspace_id == "wrkspc_test"
        assert timeout_seconds == 10
        return {
            "content": [{"type": "text", "text": json.dumps(draft_payload())}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 800, "output_tokens": 400},
        }

    monkeypatch.setattr(remediation, "_post_anthropic_payload", fake_post)
    plan = await generate_remediation_plan(
        remediation_context(),
        config=provider_config("anthropic"),
    )

    assert plan.source == "anthropic"
    assert plan.model == "claude-haiku-4-5"
    assert captured["output_config"] == {
        "format": {
            "type": "json_schema",
            "schema": remediation._anthropic_output_schema(),
        }
    }
    assert "tools" not in captured
    assert "tool_choice" not in captured
    assert plan.total_tokens == 1200
    assert plan.estimated_cost_usd == 0.0028


def test_anthropic_schema_moves_unsupported_constraints_to_descriptions() -> None:
    schema = remediation._anthropic_output_schema()
    serialized = json.dumps(schema, ensure_ascii=False)

    def schema_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(schema_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(schema_keys(item) for item in value))
        return set()

    assert not (
        {"minLength", "maxLength", "minItems", "maxItems"} & schema_keys(schema)
    )
    assert "Restrições validadas pela aplicação" in serialized


@pytest.mark.asyncio
async def test_anthropic_interrupted_output_returns_fallback(monkeypatch) -> None:
    def fake_post(payload, api_key, workspace_id, timeout_seconds):
        return {
            "content": [{"type": "text", "text": '{"why_it_matters":"incompleto"'}],
            "stop_reason": "max_tokens",
            "usage": {"input_tokens": 800, "output_tokens": 2200},
        }

    monkeypatch.setattr(remediation, "_post_anthropic_payload", fake_post)
    plan = await generate_remediation_plan(
        remediation_context(),
        config=provider_config("anthropic"),
    )

    assert plan.source == "scanner_template"
    assert plan.warning is not None
    assert "provedor pode contabilizar os tokens" in plan.warning


@pytest.mark.asyncio
async def test_anthropic_response_is_normalized_without_a_second_request(monkeypatch) -> None:
    calls = 0
    oversized = draft_payload()
    oversized["cautions"] = [f"Cuidado {index}." for index in range(7)]
    oversized["estimated_effort"] = "Estimativa detalhada " * 30

    def fake_post(payload, api_key, workspace_id, timeout_seconds):
        nonlocal calls
        calls += 1
        return {
            "content": [{"type": "text", "text": json.dumps(oversized)}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 800, "output_tokens": 400},
        }

    monkeypatch.setattr(remediation, "_post_anthropic_payload", fake_post)
    plan = await generate_remediation_plan(
        remediation_context(),
        config=provider_config("anthropic"),
    )

    assert calls == 1
    assert plan.source == "anthropic"
    assert len(plan.cautions) == 6
    assert len(plan.estimated_effort) <= 300
    assert plan.estimated_effort.endswith("…")
    assert plan.total_tokens == 1200


def test_anthropic_workspace_is_sent_as_a_request_header(monkeypatch) -> None:
    captured_headers: dict[str, str] = {}

    def fake_post_json(url, payload, headers, timeout_seconds):
        captured_headers.update(headers)
        return {"content": []}

    monkeypatch.setattr(remediation, "_post_json", fake_post_json)
    remediation._post_anthropic_payload(
        {"model": "claude-haiku-4-5"},
        "test-key",
        "wrkspc_test",
        10,
    )

    assert captured_headers["anthropic-workspace-id"] == "wrkspc_test"
    assert captured_headers["x-api-key"] == "test-key"


def test_input_signature_is_stable_and_changes_with_finding_data() -> None:
    original = remediation_context()
    same = remediation_context()
    changed = remediation_context().model_copy(update={"neo_score": 80})

    assert remediation_input_signature(original) == remediation_input_signature(same)
    assert remediation_input_signature(original) != remediation_input_signature(changed)


def test_official_references_allow_only_curated_https_sources() -> None:
    references = build_official_references(
        plugin_id=318043,
        title="Rocky Linux 9 : kernel (RLSA-2026:19568)",
        cves=["CVE-2026-23270"],
        scanner_references=[
            "https://errata.rockylinux.org/RLSA-2026:19568",
            "https://evil.example/fake-advisory",
            "http://nvd.nist.gov/vuln/detail/CVE-2026-23270",
        ],
        operating_system="Rocky Linux release 9.8",
        family="Rocky Linux Local Security Checks",
    )

    assert "https://errata.rockylinux.org/RLSA-2026:19568" in references
    assert "https://www.tenable.com/plugins/nessus/318043" in references
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-23270" in references
    assert not any("evil.example" in reference for reference in references)
    assert not any(reference.startswith("http://") for reference in references)


@pytest.mark.asyncio
async def test_replaces_kernel_update_when_evidence_says_only_reboot_is_pending(
    monkeypatch,
) -> None:
    context = remediation_context().model_copy(
        update={
            "plugin_id": 318043,
            "title": "Rocky Linux 9 : kernel (RLSA-2026:19568)",
            "family": "Rocky Linux Local Security Checks",
            "operating_system": "Rocky Linux release 9.8",
            "cvss3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "scanner_evidence": (
                "Installed package kernel-5.14.0-687.38.1.el9_8 is greater than "
                "5.14.0-687.10.1.el9_8.0.1. The current running kernel level is "
                "5.14.0-611.5.1.el9_7. This system requires a reboot."
            ),
        }
    )
    unsafe = draft_payload()
    unsafe["steps"] = ["Execute sudo dnf update kernel e depois reinicie."]

    def fake_post(payload, api_key, workspace_id, timeout_seconds):
        return {
            "content": [{"type": "text", "text": json.dumps(unsafe)}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 800, "output_tokens": 400},
        }

    monkeypatch.setattr(remediation, "_post_anthropic_payload", fake_post)
    plan = await generate_remediation_plan(context, config=provider_config("anthropic"))

    assert plan.source == "anthropic"
    assert plan.warning is None
    assert plan.total_tokens == 1200
    assert not any("dnf update" in step.lower() for step in plan.steps)
    assert any("reiniciar" in step.lower() for step in plan.steps)


@pytest.mark.asyncio
async def test_kernel_guardrail_does_not_reject_a_prohibitive_package_update_mention(
    monkeypatch,
) -> None:
    context = remediation_context().model_copy(
        update={
            "plugin_id": 318043,
            "title": "Rocky Linux 9 : kernel (RLSA-2026:19568)",
            "family": "Rocky Linux Local Security Checks",
            "operating_system": "Rocky Linux release 9.8",
            "cvss3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "scanner_evidence": (
                "Installed package kernel-5.14.0-687.38.1.el9_8 is greater than "
                "5.14.0-687.10.1.el9_8.0.1. The current running kernel level is "
                "5.14.0-611.5.1.el9_7. This system requires a reboot."
            ),
        }
    )
    safe = draft_payload()
    safe["steps"] = ["Reinicie o ativo em uma janela de manutenção autorizada."]
    safe["cautions"] = [
        "Não execute dnf update: os pacotes corrigidos já estão instalados."
    ]

    def fake_post(payload, api_key, workspace_id, timeout_seconds):
        return {
            "content": [{"type": "text", "text": json.dumps(safe)}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 800, "output_tokens": 400},
        }

    monkeypatch.setattr(remediation, "_post_anthropic_payload", fake_post)
    plan = await generate_remediation_plan(context, config=provider_config("anthropic"))

    assert plan.source == "anthropic"
    assert plan.warning is None
    assert any("reiniciar" in step.lower() for step in plan.steps)


def test_kernel_reboot_evidence_adds_deterministic_guidance() -> None:
    context = remediation_context().model_copy(
        update={
            "plugin_id": 318043,
            "title": "Rocky Linux 9 : kernel (RLSA-2026:19568)",
            "family": "Rocky Linux Local Security Checks",
            "operating_system": "Rocky Linux release 9.8",
            "cvss3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "scanner_evidence": (
                "Installed package kernel-5.14.0-687.38.1.el9_8 is greater than "
                "5.14.0-687.10.1.el9_8.0.1. The current running kernel level is "
                "5.14.0-611.5.1.el9_7. This system requires a reboot."
            ),
        }
    )

    provider_input = remediation._scanner_input(context)

    assert "DECISÃO DETERMINÍSTICA" in provider_input
    assert "reboot pendente" in provider_input
    assert "vetor de ataque local" in provider_input
    assert "5.14.0-611.5.1.el9_7" in provider_input


def test_grafana_findings_receive_vendor_specific_guidance_and_references() -> None:
    context = remediation_context().model_copy(
        update={
            "plugin_id": 304686,
            "title": "Grafana 12.1.0 < 12.1.10 DoS (CVE-2026-27880)",
            "family": "Web Servers",
            "credentialed_scan": False,
            "cves": ["CVE-2026-27880"],
        }
    )

    provider_input = remediation._scanner_input(context)
    plan = remediation.build_scanner_template(context)

    assert "método de instalação" in provider_input
    assert "scan não está marcado como credenciado" in provider_input
    assert (
        "https://grafana.com/security/security-advisories/cve-2026-27880/"
        in plan.official_references
    )
    assert "https://grafana.com/docs/grafana/latest/upgrade-guide/" in plan.official_references
