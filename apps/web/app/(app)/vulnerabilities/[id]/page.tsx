import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { PageTitle } from "@/components/page-title";
import {
  RemediationPlan,
  type RemediationPlanData,
} from "@/components/remediation-plan";
import {
  VulnerabilityWorkflow,
  type WorkflowState,
  type WorkflowStatus,
} from "@/components/vulnerability-workflow";
import {
  VulnerabilityTicketCard,
  type TicketIntegrationState,
} from "@/components/vulnerability-ticket";
import { serverApi } from "@/lib/api-server";

export const metadata: Metadata = {
  title: "Detalhe da vulnerabilidade",
};

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Priority = "act_now" | "prioritize" | "plan" | "monitor";

interface VulnerabilityDetail {
  id: number;
  title: string;
  severity: Severity;
  status: WorkflowStatus;
  family: string | null;
  synopsis: string | null;
  description: string | null;
  solution: string | null;
  plugin_output: string | null;
  cves: string[];
  asset: {
    id: number;
    address: string;
    fqdn: string | null;
    operating_system: string | null;
    credentialed: boolean;
  };
  protocol: string;
  port: number;
  service: string | null;
  risk_factor: string | null;
  cvss2: number | null;
  cvss3: number | null;
  cvss4: number | null;
  cvss3_vector: string | null;
  vpr: number | null;
  epss: number | null;
  exploitable: boolean;
  exploit_maturity: string | null;
  discovered_at: string;
  observed_at: string;
  neo_score: {
    version: string;
    total: number;
    priority: Priority;
    cvss_component: number;
    epss_component: number;
    exploit_component: number;
    vpr_component: number;
    factors: string[];
  };
  workflow: WorkflowState;
  can_generate_ai: boolean;
}

export default async function VulnerabilityDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [finding, initialRemediation, ticketIntegration] = await Promise.all([
    serverApi<VulnerabilityDetail>(`/vulnerabilities/${id}`),
    serverApi<RemediationPlanData | null>(`/vulnerabilities/${id}/remediation`),
    serverApi<TicketIntegrationState>(`/vulnerabilities/${id}/ticket`),
  ]);
  const priority = priorityCopy(finding.neo_score.priority);
  const bestCvss = finding.cvss4 ?? finding.cvss3 ?? finding.cvss2;

  return (
    <div className="page-content vulnerability-detail">
      <Link className="detail-back" href="/vulnerabilities">
        ← Voltar para vulnerabilidades
      </Link>

      <PageTitle
        eyebrow={`${severityLabel(finding.severity)} · ${finding.family ?? "Família não informada"}`}
        title={finding.title}
        description={finding.synopsis ?? "Análise técnica do achado identificado pelo scanner."}
        action={
          <div className={`neo-score-hero neo-score-hero--${finding.neo_score.priority}`}>
            <span>WVM SCORE</span>
            <strong>{finding.neo_score.total}</strong>
            <small>{priority.label}</small>
          </div>
        }
      />

      <section className="detail-summary-grid" aria-label="Resumo da vulnerabilidade">
        <Link className="panel detail-summary-card" href={`/assets/${finding.asset.id}`}>
          <span>ATIVO AFETADO</span>
          <strong>{finding.asset.fqdn ?? finding.asset.address}</strong>
          <small>{finding.asset.address}</small>
        </Link>
        <article className="panel detail-summary-card">
          <span>EXPOSIÇÃO TÉCNICA</span>
          <strong>{finding.port > 0 ? `${finding.protocol.toUpperCase()}/${finding.port}` : "Local"}</strong>
          <small>{finding.service ?? "Serviço não identificado"}</small>
        </article>
        <article className="panel detail-summary-card">
          <span>CVSS MAIS RECENTE</span>
          <strong>{bestCvss?.toFixed(1) ?? "—"}</strong>
          <small>{finding.cvss4 ? "CVSS 4" : finding.cvss3 ? "CVSS 3" : "CVSS 2 ou severidade"}</small>
        </article>
        <article className="panel detail-summary-card">
          <span>ÚLTIMA OBSERVAÇÃO</span>
          <strong>{formatDate(finding.observed_at)}</strong>
          <small>{finding.asset.credentialed ? "Scan credenciado" : "Scan não credenciado"}</small>
        </article>
      </section>

      <section className="detail-layout">
        <div className="detail-main-column">
          <DetailPanel title="Descrição técnica do scanner">
            <p>{finding.description ?? finding.synopsis ?? "O scanner não forneceu uma descrição detalhada."}</p>
            {finding.cves.length > 0 && (
              <div className="cve-list" aria-label="CVEs associados">
                {finding.cves.map((cve) => <span key={cve}>{cve}</span>)}
              </div>
            )}
          </DetailPanel>

          <DetailPanel title="Plano de correção do scanner" tone="solution">
            <p>{finding.solution ?? "O arquivo importado não trouxe uma solução específica para este achado."}</p>
          </DetailPanel>

          {finding.workflow.status === "resolved" ? (
            <DetailPanel title="Correção confirmada" tone="solution">
              <p>
                Um scan posterior do mesmo escopo não encontrou esta vulnerabilidade. O plano
                permanece preservado no histórico e será retomado automaticamente se o achado voltar.
              </p>
            </DetailPanel>
          ) : (
            <RemediationPlan
              canGenerate={finding.can_generate_ai}
              findingId={finding.id}
              initialPlan={initialRemediation}
            />
          )}

          <DetailPanel title="Evidência técnica">
            {finding.plugin_output ? (
              <pre className="plugin-evidence">{finding.plugin_output}</pre>
            ) : (
              <p>Nenhuma saída técnica adicional foi registrada pelo plugin.</p>
            )}
          </DetailPanel>
        </div>

        <aside className="detail-side-column">
          <VulnerabilityWorkflow
            findingId={finding.id}
            initialWorkflow={finding.workflow}
          />

          <VulnerabilityTicketCard
            findingId={finding.id}
            initialState={ticketIntegration}
          />

          <article className="panel score-explainer">
            <div className="score-explainer__heading">
              <div>
                <span>PRIORIDADE RECOMENDADA</span>
                <strong>{priority.label}</strong>
              </div>
              <i className={`priority-dot priority-dot--${finding.neo_score.priority}`} />
            </div>
            <p>{priority.description}</p>
            <div className="score-components">
              <ScoreComponent label="Impacto técnico" max={55} value={finding.neo_score.cvss_component} />
              <ScoreComponent label="Probabilidade EPSS" max={25} value={finding.neo_score.epss_component} />
              <ScoreComponent label="Exploit disponível" max={10} value={finding.neo_score.exploit_component} />
              <ScoreComponent label="Tenable VPR" max={10} value={finding.neo_score.vpr_component} />
            </div>
            <ul className="score-factors">
              {finding.neo_score.factors.map((factor) => <li key={factor}>{factor}</li>)}
            </ul>
            <small className="score-disclaimer">
              WVM Score v{finding.neo_score.version}: prioridade técnica transparente e auditável; não substitui a avaliação de risco do negócio.
            </small>
          </article>

          <article className="panel technical-facts">
            <h2>Contexto técnico</h2>
            <dl>
              <Fact label="Sistema operacional" value={finding.asset.operating_system} />
              <Fact label="Fator de risco" value={finding.risk_factor} />
              <Fact label="EPSS" value={finding.epss == null ? null : `${(finding.epss * 100).toFixed(2)}%`} />
              <Fact label="VPR" value={finding.vpr?.toFixed(1)} />
              <Fact label="Explorável" value={finding.exploitable ? "Sim" : "Não informado"} />
              <Fact label="Maturidade do exploit" value={finding.exploit_maturity} />
              <Fact label="Vetor CVSS 3" value={finding.cvss3_vector} />
              <Fact label="Descoberta" value={formatDate(finding.discovered_at)} />
            </dl>
          </article>
        </aside>
      </section>
    </div>
  );
}

function DetailPanel({
  title,
  tone,
  children,
}: {
  title: string;
  tone?: "solution";
  children: ReactNode;
}) {
  return (
    <article className={`panel detail-panel${tone ? ` detail-panel--${tone}` : ""}`}>
      <h2>{title}</h2>
      {children}
    </article>
  );
}

function ScoreComponent({ label, value, max }: { label: string; value: number; max: number }) {
  const width = Math.min(Math.max((value / max) * 100, 0), 100);
  return (
    <div className="score-component">
      <div><span>{label}</span><strong>{value.toFixed(1)}</strong></div>
      <div className="score-component__track"><i style={{ width: `${width}%` }} /></div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string | null | undefined }) {
  return <div><dt>{label}</dt><dd>{value || "Não informado"}</dd></div>;
}

function severityLabel(severity: Severity) {
  return {
    critical: "SEVERIDADE CRÍTICA",
    high: "SEVERIDADE ALTA",
    medium: "SEVERIDADE MÉDIA",
    low: "SEVERIDADE BAIXA",
    info: "INFORMATIVA",
  }[severity];
}

function priorityCopy(priority: Priority) {
  return {
    act_now: {
      label: "Agir agora",
      description: "Sinais combinados indicam necessidade de resposta imediata e validação da correção.",
    },
    prioritize: {
      label: "Priorizar",
      description: "Inclua este achado no próximo ciclo de remediação e confirme o responsável.",
    },
    plan: {
      label: "Planejar",
      description: "Programe o tratamento e acompanhe mudanças nos sinais de exploração.",
    },
    monitor: {
      label: "Monitorar",
      description: "Mantenha o achado visível e reavalie quando surgirem novos sinais ou contexto.",
    },
  }[priority];
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}
