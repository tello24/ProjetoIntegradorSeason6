import os

import pytest
from fastapi.testclient import TestClient

from app.api.routes import vulnerabilities as vulnerability_routes
from app.core.config import settings
from app.main import app
from app.services.remediation import RemediationPlan

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Requer PostgreSQL com as migrations aplicadas.",
)


SAMPLE_NESSUS = b"""<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Policy>
    <policyName>CI policy</policyName>
  </Policy>
  <Report name="CI Scan">
    <ReportHost name="198.51.100.10">
      <HostProperties>
        <tag name="host-ip">198.51.100.10</tag>
        <tag name="host-fqdn">ci-host.example.com</tag>
        <tag name="operating-system">Linux</tag>
        <tag name="Credentialed_Scan">true</tag>
        <tag name="bios-uuid">00000000-0000-0000-0000-000000000002</tag>
        <tag name="system-type">general-purpose</tag>
        <tag name="operating-system-conf">90</tag>
        <tag name="operating-system-method">SSH</tag>
        <tag name="local-checks-proto">ssh</tag>
        <tag name="HOST_START_TIMESTAMP">1893456000</tag>
        <tag name="HOST_END_TIMESTAMP">1893456065</tag>
        <tag name="LastAuthenticatedResults">1893456065</tag>
        <tag name="patch-summary-total-cves">1</tag>
        <tag name="policy-used">CI policy</tag>
        <tag name="cpe-0">cpe:/o:example:linux:1</tag>
      </HostProperties>
      <ReportItem
        port="443"
        svc_name="https"
        protocol="tcp"
        severity="4"
        pluginID="900001"
        pluginName="Synthetic critical finding"
        pluginFamily="General"
      >
        <risk_factor>Critical</risk_factor>
        <cvss3_base_score>9.8</cvss3_base_score>
        <cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector>
        <synopsis>Synthetic test finding.</synopsis>
        <description>Used only by the automated integration test.</description>
        <solution>Apply the synthetic test fix.</solution>
        <plugin_output>The installed synthetic package was observed by the scanner.</plugin_output>
        <see_also>https://www.tenable.com/plugins/nessus/900001</see_also>
        <exploit_available>true</exploit_available>
        <cve>CVE-2099-0001</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

SECOND_SAMPLE_NESSUS = (
    SAMPLE_NESSUS.replace(b' name="CI Scan"', b' name="CI Retest"')
    .replace(b'pluginID="900001"', b'pluginID="900002"')
    .replace(b"CVE-2099-0001", b"CVE-2099-0002")
)

THIRD_SAMPLE_NESSUS = SAMPLE_NESSUS.replace(
    b' name="CI Scan"',
    b' name="CI Regression Check"',
)


def test_login_import_and_reporting_flow(monkeypatch) -> None:
    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@neoguardian.com",
                "password": "ci-only-strong-password-2026!",
            },
        )
        assert login.status_code == 200
        assert login.json()["user"]["client_name"] == "Ambiente CI"
        user_id = login.json()["user"]["id"]
        assert client.cookies.get("ng_session")

        imported = client.post(
            "/api/v1/scans/import",
            files={"file": ("ci-scan.nessus", SAMPLE_NESSUS, "application/xml")},
        )
        assert imported.status_code == 202

        import_id = imported.json()["id"]
        import_status = client.get(f"/api/v1/scans/imports/{import_id}")
        assert import_status.status_code == 200
        assert import_status.json()["status"] == "concluido"
        assert import_status.json()["assets"] == 1
        assert import_status.json()["findings"] == 1
        assert import_status.json()["resolved"] == 0
        assert import_status.json()["reopened"] == 0

        scans = client.get("/api/v1/scans")
        assert scans.status_code == 200
        assert scans.json()["total"] == 1
        assert scans.json()["can_import"] is True
        assert scans.json()["items"][0]["name"] == "CI Scan"

        scanner_sources = client.get("/api/v1/scans/sources")
        assert scanner_sources.status_code == 200
        assert scanner_sources.json() == [
            {
                "key": "nessus",
                "display_name": "Tenable Nessus",
                "extensions": [".nessus"],
            }
        ]

        dashboard = client.get("/api/v1/dashboard/summary")
        assert dashboard.status_code == 200
        assert dashboard.json()["assets"] == 1
        assert dashboard.json()["open_vulnerabilities"] == 1
        assert dashboard.json()["critical"] == 1
        assert dashboard.json()["medium"] == 0
        assert dashboard.json()["low"] == 0
        assert dashboard.json()["urgent_findings"] == 0
        assert dashboard.json()["top_assets"][0]["name"] == "ci-host.example.com"
        assert dashboard.json()["top_assets"][0]["risk_score"] == 10
        assert dashboard.json()["risk_trend"][0]["name"] == "CI Scan"
        assert dashboard.json()["workflow"]["unassigned"] == 1
        assert dashboard.json()["workflow"]["resolved_this_week"] == 0
        assert dashboard.json()["workflow"]["reopened_last_30_days"] == 0
        assert dashboard.json()["workflow"]["resolution_rate"] == 0
        assert dashboard.json()["workflow"]["open"] == 1
        assert dashboard.json()["workflow"]["reopened"] == 0
        assert dashboard.json()["reliability"]["level"] == "healthy"
        assert dashboard.json()["reliability"]["credentialed_percentage"] == 100
        assert dashboard.json()["reliability"]["failed_imports_last_30_days"] == 0
        assert dashboard.json()["scope_options"][0]["label"] == "CI Scan"
        assert dashboard.json()["scope_options"][0]["assets"] == 1

        scope_key = scans.json()["items"][0]["scope_key"]
        filtered_dashboard = client.get(
            "/api/v1/dashboard/summary",
            params={"scope_key": scope_key, "severity": "critical"},
        )
        assert filtered_dashboard.status_code == 200
        assert filtered_dashboard.json()["open_vulnerabilities"] == 1
        assert filtered_dashboard.json()["applied_filters"] == {
            "scope_key": scope_key,
            "severity": "critical",
        }

        empty_severity_dashboard = client.get(
            "/api/v1/dashboard/summary",
            params={"severity": "high"},
        )
        assert empty_severity_dashboard.status_code == 200
        assert empty_severity_dashboard.json()["assets"] == 1
        assert empty_severity_dashboard.json()["open_vulnerabilities"] == 0
        assert client.get(
            "/api/v1/dashboard/summary",
            params={"scope_key": "not-a-client-scope"},
        ).status_code == 422

        assets = client.get("/api/v1/assets")
        assert assets.status_code == 200
        assert assets.json()["summary"] == {
            "total": 1,
            "critical_exposure": 1,
            "credentialed": 1,
            "uncredentialed": 0,
            "clean": 0,
            "critical_business_assets": 0,
            "critical_business_exposure": 0,
            "production_uncredentialed": 0,
            "without_owner": 1,
        }
        assert assets.json()["items"][0]["name"] == "ci-host.example.com"
        assert assets.json()["items"][0]["vulnerabilities"] == 1
        assert assets.json()["items"][0]["risk_score"] == 64

        asset_id = assets.json()["items"][0]["id"]
        asset_detail = client.get(f"/api/v1/assets/{asset_id}")
        assert asset_detail.status_code == 200
        assert asset_detail.json()["address"] == "198.51.100.10"
        assert asset_detail.json()["credentialed"] is True
        assert asset_detail.json()["facts"] == {
            "netbios": None,
            "mac": None,
            "system_type": "general-purpose",
            "bios_uuid": "00000000-0000-0000-0000-000000000002",
            "cpes": ["cpe:/o:example:linux:1"],
            "operating_system_confidence": 90,
            "operating_system_method": "SSH",
        }
        assert asset_detail.json()["coverage"]["credentialed"] is True
        assert asset_detail.json()["coverage"]["local_checks_protocol"] == "ssh"
        assert asset_detail.json()["coverage"]["duration_seconds"] == 65
        assert asset_detail.json()["coverage"]["policy_used"] == "CI policy"
        assert asset_detail.json()["inventory"]["scans_observed"] == 1
        assert asset_detail.json()["inventory"]["observed_services"] == 1
        assert asset_detail.json()["inventory"]["services_with_findings"] == 1
        assert asset_detail.json()["inventory"]["patch_summary_total_cves"] == 1
        assert asset_detail.json()["changes"]["available"] is False
        assert asset_detail.json()["business_context"]["environment"] is None
        assert asset_detail.json()["business_context"]["can_edit"] is True
        assert asset_detail.json()["services"] == [
            {
                "protocol": "tcp",
                "port": 443,
                "service": "https",
                "vulnerabilities": 1,
                "highest_severity": "critical",
                "risk_score": 64,
                "observed_at": "2030-01-01T00:01:05Z",
            }
        ]
        assert asset_detail.json()["vulnerabilities_list"][0]["title"] == (
            "Synthetic critical finding"
        )
        assert asset_detail.json()["vulnerabilities_list"][0]["neo_score"] == 64
        assert len(asset_detail.json()["scan_history"]) == 1
        assert client.get("/api/v1/assets/999999").status_code == 404

        context_options = client.get("/api/v1/assets/context-options")
        assert context_options.status_code == 200
        assert context_options.json()["owners"][0]["id"] == user_id

        business_context = client.patch(
            f"/api/v1/assets/{asset_id}/business-context",
            json={
                "environment": "producao",
                "business_criticality": "critica",
                "owner_id": user_id,
                "responsible_team": "Infraestrutura",
                "business_service": "Portal sintético",
                "business_unit": "Operações",
                "internet_exposed": True,
                "maintenance_window": "Domingos, 02h às 05h",
                "tags": ["PCI", "produção", "pci"],
                "notes": "Contexto criado pelo teste de integração.",
            },
        )
        assert business_context.status_code == 200
        assert business_context.json()["environment"] == "producao"
        assert business_context.json()["business_criticality"] == "critica"
        assert business_context.json()["owner"]["id"] == user_id
        assert business_context.json()["tags"] == ["PCI", "produção"]
        assert business_context.json()["can_edit"] is True

        partial_context_update = client.patch(
            f"/api/v1/assets/{asset_id}/business-context",
            json={"responsible_team": "Plataforma"},
        )
        assert partial_context_update.status_code == 200
        assert partial_context_update.json()["environment"] == "producao"
        assert partial_context_update.json()["owner"]["id"] == user_id
        assert partial_context_update.json()["responsible_team"] == "Plataforma"
        context_updated_at = partial_context_update.json()["updated_at"]

        unchanged_context = client.patch(
            f"/api/v1/assets/{asset_id}/business-context",
            json={"responsible_team": "Plataforma"},
        )
        assert unchanged_context.status_code == 200
        assert unchanged_context.json()["updated_at"] == context_updated_at

        contextualized_assets = client.get("/api/v1/assets")
        assert contextualized_assets.status_code == 200
        assert contextualized_assets.json()["summary"]["critical_business_assets"] == 1
        assert contextualized_assets.json()["summary"]["critical_business_exposure"] == 1
        assert contextualized_assets.json()["summary"]["without_owner"] == 0
        assert contextualized_assets.json()["items"][0]["environment"] == "producao"
        assert contextualized_assets.json()["items"][0]["business_owner_name"] == (
            "Administrador CI"
        )

        vulnerabilities = client.get(
            "/api/v1/vulnerabilities",
            params={"search": "CVE-2099-0001", "severity": "critical"},
        )
        assert vulnerabilities.status_code == 200
        assert vulnerabilities.json()["total"] == 1
        assert vulnerabilities.json()["items"][0]["asset"] == "ci-host.example.com"
        assert vulnerabilities.json()["items"][0]["cvss"] == 9.8
        assert vulnerabilities.json()["items"][0]["neo_score"] == 64
        assert vulnerabilities.json()["summary"] == {
            "active": 1,
            "resolved": 0,
            "accepted_risk": 0,
            "reopened": 0,
            "total": 1,
        }

        remediation_queue = client.get("/api/v1/vulnerabilities/queue")
        assert remediation_queue.status_code == 200
        assert remediation_queue.json()["total"] == 1
        assert remediation_queue.json()["can_edit"] is True
        assert remediation_queue.json()["can_accept_risk"] is True
        assert remediation_queue.json()["summary"] == {
            "total_active": 1,
            "act_now": 0,
            "overdue": 0,
            "due_soon": 1,
            "unassigned": 1,
            "reopened": 0,
            "quick_wins": 0,
        }
        queue_item = remediation_queue.json()["items"][0]
        assert queue_item["neo_score"] == 64
        assert queue_item["reason"] == "unassigned"
        assert queue_item["due_source"] == "sla"
        assert queue_item["sla_days"] == 7
        assert queue_item["occurrence_count"] == 1

        unassigned_queue = client.get(
            "/api/v1/vulnerabilities/queue",
            params={"focus": "unassigned", "severity": "critical"},
        )
        assert unassigned_queue.status_code == 200
        assert unassigned_queue.json()["total"] == 1

        finding_id = vulnerabilities.json()["items"][0]["id"]
        detail = client.get(f"/api/v1/vulnerabilities/{finding_id}")
        assert detail.status_code == 200
        assert detail.json()["neo_score"]["total"] == 64
        assert detail.json()["neo_score"]["priority"] == "prioritize"
        assert detail.json()["asset"]["credentialed"] is True
        assert detail.json()["solution"] == "Apply the synthetic test fix."
        assert "installed synthetic package" in detail.json()["plugin_output"]
        assert detail.json()["workflow"]["status"] == "open"
        assert detail.json()["workflow"]["id"] is not None
        assert detail.json()["workflow"]["resolution_count"] == 0
        assert detail.json()["workflow"]["reopen_count"] == 0
        assert detail.json()["workflow"]["can_accept_risk"] is True
        assert detail.json()["can_generate_ai"] is True

        access_list = client.get("/api/v1/access/users")
        assert access_list.status_code == 200
        assert access_list.json()["total"] == 1
        assert access_list.json()["items"][0]["is_current_user"] is True

        self_demotion = client.patch(
            f"/api/v1/access/users/{user_id}",
            json={"role": "visualizador"},
        )
        assert self_demotion.status_code == 409

        role_password = "Role-test-password-2026!"
        created_users: dict[str, dict[str, object]] = {}
        for role, name in (
            ("gestor", "Gestor RBAC"),
            ("analista", "Analista RBAC"),
            ("visualizador", "Visualizador RBAC"),
        ):
            created = client.post(
                "/api/v1/access/users",
                json={
                    "name": name,
                    "email": f"{role}@rbac.example.com",
                    "temporary_password": role_password,
                    "role": role,
                },
            )
            assert created.status_code == 201
            assert created.json()["role"] == role
            created_users[role] = created.json()

        duplicate_user = client.post(
            "/api/v1/access/users",
            json={
                "name": "Gestor duplicado",
                "email": "gestor@rbac.example.com",
                "temporary_password": role_password,
                "role": "gestor",
            },
        )
        assert duplicate_user.status_code == 409

        visualizer_id = created_users["visualizador"]["id"]
        deactivated = client.patch(
            f"/api/v1/access/users/{visualizer_id}",
            json={"active": False},
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False

        blocked_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "visualizador@rbac.example.com",
                "password": role_password,
            },
        )
        assert blocked_login.status_code == 401

        reactivated = client.patch(
            f"/api/v1/access/users/{visualizer_id}",
            json={"active": True},
        )
        assert reactivated.status_code == 200
        assert reactivated.json()["active"] is True

        manager_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "gestor@rbac.example.com",
                "password": role_password,
            },
        )
        assert manager_login.status_code == 200
        assert manager_login.json()["user"]["role"] == "gestor"
        assert client.get("/api/v1/access/users").status_code == 403
        manager_scans = client.get("/api/v1/scans")
        assert manager_scans.status_code == 200
        assert manager_scans.json()["can_import"] is False
        assert client.post(
            "/api/v1/scans/import",
            files={"file": ("blocked.nessus", SAMPLE_NESSUS, "application/xml")},
        ).status_code == 403
        manager_queue = client.get("/api/v1/vulnerabilities/queue")
        assert manager_queue.status_code == 200
        assert manager_queue.json()["can_edit"] is True
        assert manager_queue.json()["can_accept_risk"] is True
        assert client.post(
            f"/api/v1/vulnerabilities/{finding_id}/remediation"
        ).status_code == 403

        analyst_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "analista@rbac.example.com",
                "password": role_password,
            },
        )
        assert analyst_login.status_code == 200
        assert analyst_login.json()["user"]["role"] == "analista"
        analyst_scans = client.get("/api/v1/scans")
        assert analyst_scans.status_code == 200
        assert analyst_scans.json()["can_import"] is True
        analyst_queue = client.get("/api/v1/vulnerabilities/queue")
        assert analyst_queue.status_code == 200
        assert analyst_queue.json()["can_edit"] is True
        assert analyst_queue.json()["can_accept_risk"] is False
        assert client.patch(
            f"/api/v1/vulnerabilities/{finding_id}/workflow",
            json={"status": "accepted_risk"},
        ).status_code == 403

        visualizer_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "visualizador@rbac.example.com",
                "password": role_password,
            },
        )
        assert visualizer_login.status_code == 200
        assert visualizer_login.json()["user"]["role"] == "visualizador"
        visualizer_queue = client.get("/api/v1/vulnerabilities/queue")
        assert visualizer_queue.status_code == 200
        assert visualizer_queue.json()["can_edit"] is False
        assert visualizer_queue.json()["can_accept_risk"] is False
        visualizer_detail = client.get(f"/api/v1/vulnerabilities/{finding_id}")
        assert visualizer_detail.status_code == 200
        assert visualizer_detail.json()["workflow"]["can_edit"] is False
        assert visualizer_detail.json()["can_generate_ai"] is False
        visualizer_asset = client.get(f"/api/v1/assets/{asset_id}")
        assert visualizer_asset.status_code == 200
        assert visualizer_asset.json()["business_context"]["can_edit"] is False
        assert client.patch(
            f"/api/v1/assets/{asset_id}/business-context",
            json={"environment": "laboratorio"},
        ).status_code == 403
        assert client.patch(
            f"/api/v1/vulnerabilities/{finding_id}/workflow",
            json={"status": "triage"},
        ).status_code == 403
        visualizer_ticket = client.get(
            f"/api/v1/vulnerabilities/{finding_id}/ticket"
        )
        assert visualizer_ticket.status_code == 200
        assert visualizer_ticket.json()["can_create"] is False

        restored_admin = client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@neoguardian.com",
                "password": "ci-only-strong-password-2026!",
            },
        )
        assert restored_admin.status_code == 200
        assert restored_admin.json()["user"]["role"] == "administrador"

        access_list = client.get("/api/v1/access/users")
        assert access_list.status_code == 200
        assert access_list.json()["total"] == 4

        ticket_integration = client.get(
            f"/api/v1/vulnerabilities/{finding_id}/ticket"
        )
        assert ticket_integration.status_code == 200
        assert ticket_integration.json()["enabled"] is (settings.active_jira is not None)
        assert ticket_integration.json()["can_create"] is (settings.active_jira is not None)
        assert ticket_integration.json()["ticket"] is None

        assignees = client.get("/api/v1/vulnerabilities/assignees")
        assert assignees.status_code == 200
        assert assignees.json()[0]["id"] == user_id

        workflow = client.patch(
            f"/api/v1/vulnerabilities/{finding_id}/workflow",
            json={
                "status": "in_progress",
                "assignee_id": user_id,
                "due_date": "2099-12-31",
                "note": "Correção sintética atribuída pelo teste.",
            },
        )
        assert workflow.status_code == 200
        assert workflow.json()["status"] == "in_progress"
        assert workflow.json()["assignee"]["id"] == user_id
        assert workflow.json()["due_date"] == "2099-12-31"

        assigned_queue = client.get(
            "/api/v1/vulnerabilities/queue",
            params={"assignee_id": user_id, "status": "in_progress"},
        )
        assert assigned_queue.status_code == 200
        assert assigned_queue.json()["total"] == 1
        assert assigned_queue.json()["items"][0]["assignee_id"] == user_id
        assert assigned_queue.json()["items"][0]["due_source"] == "manual"
        assert assigned_queue.json()["summary"]["unassigned"] == 0

        history = client.get(f"/api/v1/vulnerabilities/{finding_id}/history")
        assert history.status_code == 200
        assert len(history.json()["items"]) == 1
        assert history.json()["items"][0]["action"] == "workflow.updated"

        filtered = client.get(
            "/api/v1/vulnerabilities",
            params={"status": "in_progress"},
        )
        assert filtered.status_code == 200
        assert filtered.json()["total"] == 1
        assert filtered.json()["items"][0]["assignee_name"]

        workflow_dashboard = client.get("/api/v1/dashboard/summary")
        assert workflow_dashboard.status_code == 200
        assert workflow_dashboard.json()["workflow"]["in_progress"] == 1
        assert workflow_dashboard.json()["workflow"]["unassigned"] == 0

        assert client.get(f"/api/v1/vulnerabilities/{finding_id}/remediation").json() is None
        ai_calls = 0

        async def fake_ai_generation(context, *, config):
            nonlocal ai_calls
            ai_calls += 1
            assert context.scanner_evidence is not None
            assert context.scanner_references == [
                "https://www.tenable.com/plugins/nessus/900001"
            ]
            return RemediationPlan(
                why_it_matters="A falha sintética pode comprometer o serviço de teste.",
                summary="Resumo sintético.",
                priority_rationale="Prioridade sintética.",
                prerequisites=["Confirmar janela."],
                steps=["Apply the synthetic test fix."],
                validation_steps=["Executar novo scan."],
                rollback_plan=["Restaurar o estado anterior."],
                cautions=["Validar em homologação."],
                estimated_effort="Uma hora.",
                source="anthropic",
                model="claude-haiku-4-5",
                prompt_version="ci-v1",
                input_tokens=800,
                output_tokens=400,
                total_tokens=1200,
                estimated_cost_usd=0.0028,
            )

        monkeypatch.setattr(
            vulnerability_routes,
            "generate_remediation_plan",
            fake_ai_generation,
        )
        remediation = client.post(f"/api/v1/vulnerabilities/{finding_id}/remediation")
        assert remediation.status_code == 200
        assert remediation.json()["source"] == "anthropic"
        assert remediation.json()["model"] == "claude-haiku-4-5"
        assert remediation.json()["version"] == 1
        assert remediation.json()["cached"] is False
        assert "Apply the synthetic test fix." in remediation.json()["steps"]
        assert ai_calls == 1

        cached_remediation = client.post(f"/api/v1/vulnerabilities/{finding_id}/remediation")
        assert cached_remediation.status_code == 200
        assert cached_remediation.json()["cached"] is True
        assert cached_remediation.json()["version"] == 1
        assert ai_calls == 1

        regenerated = client.post(
            f"/api/v1/vulnerabilities/{finding_id}/remediation/regenerate"
        )
        assert regenerated.status_code == 200
        assert regenerated.json()["version"] == 2
        assert regenerated.json()["previous_versions"] == 1
        assert ai_calls == 2

        ai_history = client.get(
            f"/api/v1/vulnerabilities/{finding_id}/remediation/history"
        )
        assert ai_history.status_code == 200
        assert len(ai_history.json()["items"]) == 1
        assert ai_history.json()["items"][0]["version"] == 1

        second_import = client.post(
            "/api/v1/scans/import",
            files={"file": ("ci-retest.nessus", SECOND_SAMPLE_NESSUS, "application/xml")},
        )
        assert second_import.status_code == 202
        second_import_id = second_import.json()["id"]
        second_status = client.get(f"/api/v1/scans/imports/{second_import_id}")
        assert second_status.status_code == 200
        assert second_status.json()["status"] == "concluido"
        assert second_status.json()["resolved"] == 1
        assert second_status.json()["reopened"] == 0

        second_scan_id = second_status.json()["scan_id"]
        comparison = client.get(f"/api/v1/scans/{second_scan_id}/comparison")
        assert comparison.status_code == 200
        assert comparison.json()["previous_scan_id"] == import_status.json()["scan_id"]
        assert comparison.json()["new_findings"] == 1
        assert comparison.json()["reopened_findings"] == 0
        assert comparison.json()["resolved_findings"] == 1
        assert comparison.json()["persistent_findings"] == 0
        assert comparison.json()["direction"] == "stable"
        assert comparison.json()["current_risk_score"] == 10
        assert comparison.json()["previous_risk_score"] == 10
        assert comparison.json()["risk_delta"] == 0
        assert comparison.json()["filtered_total"] == 2
        assert {item["category"] for item in comparison.json()["items"]} == {
            "new",
            "resolved",
        }
        assert comparison.json()["severity_breakdown"][0] == {
            "severity": "critical",
            "new_findings": 1,
            "reopened_findings": 0,
            "resolved_findings": 1,
            "persistent_findings": 0,
        }
        assert comparison.json()["assets_stable"] == 1

        new_comparison = client.get(
            f"/api/v1/scans/{second_scan_id}/comparison",
            params={"category": "new", "severity": "critical", "search": "900002"},
        )
        assert new_comparison.status_code == 200
        assert new_comparison.json()["filtered_total"] == 1
        assert len(new_comparison.json()["items"]) == 1
        assert new_comparison.json()["items"][0]["plugin_id"] == 900002
        assert new_comparison.json()["items"][0]["neo_score_after"] == 64
        assert new_comparison.json()["items"][0]["neo_score_before"] is None

        resolved = client.get(
            "/api/v1/vulnerabilities",
            params={"view": "resolved"},
        )
        assert resolved.status_code == 200
        assert resolved.json()["total"] == 1
        assert resolved.json()["items"][0]["id"] == finding_id
        assert resolved.json()["items"][0]["status"] == "resolved"

        resolved_detail = client.get(f"/api/v1/vulnerabilities/{finding_id}")
        assert resolved_detail.status_code == 200
        assert resolved_detail.json()["workflow"]["status"] == "resolved"
        assert resolved_detail.json()["workflow"]["resolution_count"] == 1
        assert resolved_detail.json()["workflow"]["resolved_at"] is not None
        assert resolved_detail.json()["workflow"]["can_edit"] is False

        blocked_manual_reopen = client.patch(
            f"/api/v1/vulnerabilities/{finding_id}/workflow",
            json={"status": "reopened"},
        )
        assert blocked_manual_reopen.status_code == 409

        resolved_history = client.get(f"/api/v1/vulnerabilities/{finding_id}/history")
        assert resolved_history.status_code == 200
        assert [item["action"] for item in resolved_history.json()["items"]] == [
            "workflow.auto_resolved",
            "workflow.updated",
        ]

        resolved_dashboard = client.get("/api/v1/dashboard/summary")
        assert resolved_dashboard.status_code == 200
        assert resolved_dashboard.json()["resolved_this_week"] == 1
        assert resolved_dashboard.json()["workflow"]["resolved_last_30_days"] == 1

        third_import = client.post(
            "/api/v1/scans/import",
            files={
                "file": (
                    "ci-regression.nessus",
                    THIRD_SAMPLE_NESSUS,
                    "application/xml",
                )
            },
        )
        assert third_import.status_code == 202
        third_status = client.get(
            f"/api/v1/scans/imports/{third_import.json()['id']}"
        )
        assert third_status.status_code == 200
        assert third_status.json()["status"] == "concluido"
        assert third_status.json()["resolved"] == 1
        assert third_status.json()["reopened"] == 1

        third_comparison = client.get(
            f"/api/v1/scans/{third_status.json()['scan_id']}/comparison"
        )
        assert third_comparison.status_code == 200
        assert third_comparison.json()["new_findings"] == 0
        assert third_comparison.json()["reopened_findings"] == 1
        assert third_comparison.json()["resolved_findings"] == 1
        assert third_comparison.json()["persistent_findings"] == 0

        first_to_third = client.get(
            f"/api/v1/scans/{third_status.json()['scan_id']}/comparison",
            params={"baseline_scan_id": import_status.json()["scan_id"]},
        )
        assert first_to_third.status_code == 200
        assert first_to_third.json()["previous_scan_id"] == import_status.json()["scan_id"]
        assert first_to_third.json()["new_findings"] == 0
        assert first_to_third.json()["reopened_findings"] == 0
        assert first_to_third.json()["resolved_findings"] == 0
        assert first_to_third.json()["persistent_findings"] == 1
        assert first_to_third.json()["items"][0]["category"] == "persistent"

        invalid_order = client.get(
            f"/api/v1/scans/{second_scan_id}/comparison",
            params={"baseline_scan_id": third_status.json()["scan_id"]},
        )
        assert invalid_order.status_code == 409

        reopened = client.get(
            "/api/v1/vulnerabilities",
            params={"view": "reopened"},
        )
        assert reopened.status_code == 200
        assert reopened.json()["total"] == 1
        assert reopened.json()["items"][0]["status"] == "reopened"

        reopened_detail = client.get(
            f"/api/v1/vulnerabilities/{reopened.json()['items'][0]['id']}"
        )
        assert reopened_detail.status_code == 200
        assert reopened_detail.json()["workflow"]["resolution_count"] == 1
        assert reopened_detail.json()["workflow"]["reopen_count"] == 1
        assert reopened_detail.json()["workflow"]["can_edit"] is True

        lifecycle_history = client.get(
            f"/api/v1/vulnerabilities/{reopened.json()['items'][0]['id']}/history"
        )
        assert lifecycle_history.status_code == 200
        assert [item["action"] for item in lifecycle_history.json()["items"]] == [
            "workflow.auto_reopened",
            "workflow.auto_resolved",
            "workflow.updated",
        ]

        lifecycle_dashboard = client.get("/api/v1/dashboard/summary")
        assert lifecycle_dashboard.status_code == 200
        assert lifecycle_dashboard.json()["workflow"]["reopened_last_30_days"] == 1
        assert lifecycle_dashboard.json()["workflow"]["resolved_last_30_days"] == 1

        monthly_report = client.get(
            "/api/v1/reports/monthly",
            params={"months": 6},
        )
        assert monthly_report.status_code == 200
        monthly_payload = monthly_report.json()
        assert monthly_payload["months"] == 6
        assert monthly_payload["severity"] is None
        assert monthly_payload["summary"]["scans"] == 3
        assert monthly_payload["summary"]["new_findings"] == 2
        assert monthly_payload["summary"]["resolved_findings"] == 2
        assert monthly_payload["summary"]["reopened_findings"] == 1
        assert monthly_payload["summary"]["net_change"] == 1
        assert monthly_payload["summary"]["current_backlog"] == 1
        assert monthly_payload["timeline"][-1]["scans"] == 3
        assert monthly_payload["timeline"][-1]["new_findings"] == 2
        assert monthly_payload["timeline"][-1]["resolved_findings"] == 2
        assert monthly_payload["timeline"][-1]["reopened_findings"] == 1
        assert monthly_payload["timeline"][-1]["backlog"] == 1

        critical_report = client.get(
            "/api/v1/reports/monthly",
            params={"months": 6, "severity": "critical"},
        )
        assert critical_report.status_code == 200
        assert critical_report.json()["summary"]["current_backlog"] == 1
        assert client.get(
            "/api/v1/reports/monthly",
            params={"months": 2},
        ).status_code == 422

        report_csv = client.get(
            "/api/v1/reports/monthly.csv",
            params={"months": 6},
        )
        assert report_csv.status_code == 200
        assert report_csv.headers["content-type"].startswith("text/csv")
        assert "Backlog ao final do mês" in report_csv.text

        updated_asset = client.get(f"/api/v1/assets/{asset_id}")
        assert updated_asset.status_code == 200
        assert updated_asset.json()["vulnerabilities"] == 1
        assert len(updated_asset.json()["vulnerabilities_list"]) == 1
        assert updated_asset.json()["vulnerabilities_list"][0]["status"] == "reopened"
        assert len(updated_asset.json()["scan_history"]) == 3
        assert updated_asset.json()["changes"]["available"] is True
        assert updated_asset.json()["changes"]["new_findings"] == 1
        assert updated_asset.json()["changes"]["corrected_findings"] == 1
        assert updated_asset.json()["changes"]["persistent_findings"] == 0
        assert updated_asset.json()["changes"]["reopened_findings"] == 1

        logout = client.post("/api/v1/auth/logout")
        assert logout.status_code == 204
        assert client.get("/api/v1/auth/me").status_code == 401
        assert client.get("/api/v1/reports/monthly").status_code == 401
