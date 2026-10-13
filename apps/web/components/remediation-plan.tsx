"use client";

import { useState } from "react";

import { browserApi, readApiError } from "@/lib/api";

export interface RemediationPlanData {
  why_it_matters: string;
  summary: string;
  priority_rationale: string;
  evidence_summary: string[];
  assumptions: string[];
  official_references: string[];
  prerequisites: string[];
  steps: string[];
  validation_steps: string[];
  rollback_plan: string[];
  cautions: string[];
  estimated_effort: string;
  source: "anthropic" | "openai" | "scanner_template";
  model: string | null;
  prompt_version: string | null;
  cached: boolean;
  version: number | null;
  previous_versions: number;
  generated_at: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  total_tokens: number | null;
  estimated_cost_usd: number | null;
  stale: boolean;
  can_regenerate: boolean;
  warning: string | null;
}

export function RemediationPlan({
  findingId,
  initialPlan,
  canGenerate,
}: {
  findingId: number;
  initialPlan: RemediationPlanData | null;
  canGenerate: boolean;
}) {
  const [plan, setPlan] = useState<RemediationPlanData | null>(initialPlan);
  const [history, setHistory] = useState<RemediationPlanData[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generatePlan(regenerate = false) {
    if (
      regenerate
      && !window.confirm(
        "Gerar uma nova versão consumirá tokens. A versão atual ficará preservada no histórico. Continuar?",
      )
    ) {
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const suffix = regenerate ? "/regenerate" : "";
      const response = await browserApi(`/vulnerabilities/${findingId}/remediation${suffix}`, {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response));
      }
      setPlan((await response.json()) as RemediationPlanData);
      if (regenerate) {
        setHistory(null);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Não foi possível gerar a análise.");
    } finally {
      setLoading(false);
    }
  }

  async function loadHistory() {
    if (history !== null) {
      setHistory(null);
      return;
    }

    setLoadingHistory(true);
    setError(null);
    try {
      const response = await browserApi(`/vulnerabilities/${findingId}/remediation/history`);
      if (!response.ok) {
        throw new Error(await readApiError(response));
      }
      const payload = (await response.json()) as { items: RemediationPlanData[] };
      setHistory(payload.items);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Não foi possível abrir o histórico.");
    } finally {
      setLoadingHistory(false);
    }
  }

  return (
    <article className="panel detail-panel ai-remediation">
      <div className="ai-remediation__heading">
        <div>
          <span>ASSISTENTE DE REMEDIAÇÃO</span>
          <h2>Explicação e plano de correção</h2>
        </div>
        {plan && <SourceBadge plan={plan} />}
      </div>

      {!plan && (
        <div className="ai-remediation__intro">
          <div>
            <p>
              A IA traduz o risco para uma linguagem simples e cria uma estratégia revisável com
              pré-requisitos, execução, validação e rollback.
            </p>
            <small>
              O resultado será salvo: abrir esta página novamente não fará uma nova cobrança.
              Endereço do ativo e evidências sensíveis não são enviados ao provedor.
            </small>
          </div>
          {canGenerate ? (
            <button
              className="button button--primary"
              disabled={loading}
              onClick={() => generatePlan(false)}
              type="button"
            >
              {loading ? "GERANDO ANÁLISE..." : "✦ GERAR ANÁLISE UMA VEZ"}
            </button>
          ) : (
            <small className="ai-remediation__readonly">
              Solicite a geração a um analista ou administrador.
            </small>
          )}
        </div>
      )}

      {error && <p className="form-error" role="alert">{error}</p>}

      {plan && (
        <div className="ai-plan">
          {plan.warning && <p className="ai-plan__warning" role="status">{plan.warning}</p>}
          {plan.stale && (
            <p className="ai-plan__warning" role="status">
              O scanner trouxe dados mais recentes depois desta geração. A versão continua válida
              como histórico, mas um administrador pode atualizá-la.
            </p>
          )}

          <section className="ai-plan__why">
            <span>POR QUE ISSO IMPORTA</span>
            <p>{plan.why_it_matters}</p>
          </section>

          <p className="ai-plan__summary">{plan.summary}</p>
          <div className="ai-plan__rationale">
            <span>POR QUE PRIORIZAR</span>
            <p>{plan.priority_rationale}</p>
          </div>
          <div className="ai-plan__evidence-grid">
            <PlanList title="Evidências consideradas" items={plan.evidence_summary} />
            {plan.assumptions.length > 0 && (
              <PlanList title="Confirmar antes de agir" items={plan.assumptions} />
            )}
          </div>
          <PlanList title="Antes de começar" items={plan.prerequisites} />
          <PlanList numbered title="Execução sugerida" items={plan.steps} />
          <PlanList title="Como validar" items={plan.validation_steps} />
          <div className="ai-plan__columns">
            <PlanList title="Rollback" items={plan.rollback_plan} />
            <PlanList title="Cuidados" items={plan.cautions} />
          </div>

          <div className="ai-plan__footer">
            <p><span>ESFORÇO ESTIMADO</span>{plan.estimated_effort}</p>
            {plan.can_regenerate && (
              <button
                className="button button--secondary"
                disabled={loading}
                onClick={() => generatePlan(true)}
                type="button"
              >
                {loading ? "GERANDO..." : "GERAR NOVA VERSÃO"}
              </button>
            )}
          </div>

          <PlanMetadata plan={plan} />
          {plan.official_references.length > 0 && (
            <OfficialReferences references={plan.official_references} />
          )}
          {plan.previous_versions > 0 && (
            <section className="ai-plan__history">
              <button
                className="ai-plan__history-toggle"
                disabled={loadingHistory}
                onClick={loadHistory}
                type="button"
              >
                {loadingHistory
                  ? "CARREGANDO HISTÓRICO..."
                  : history === null
                    ? `VER ${plan.previous_versions} VERSÃO(ÕES) ANTERIOR(ES)`
                    : "OCULTAR VERSÕES ANTERIORES"}
              </button>
              {history && (
                <div className="ai-plan__history-list">
                  {history.map((previous) => (
                    <details key={previous.version}>
                      <summary>
                        Versão {previous.version} · {previous.model} · {previous.generated_at
                          ? formatDate(previous.generated_at)
                          : "data não informada"}
                      </summary>
                      <div>
                        <strong>Por que isso importa</strong>
                        <p>{previous.why_it_matters}</p>
                        <strong>Resumo do plano</strong>
                        <p>{previous.summary}</p>
                        <PlanList numbered title="Execução sugerida" items={previous.steps} />
                      </div>
                    </details>
                  ))}
                </div>
              )}
            </section>
          )}
          <small className="ai-plan__disclaimer">
            Apoio à decisão: revise com o responsável técnico antes de qualquer mudança. A
            plataforma não executa correções automaticamente.
          </small>
        </div>
      )}
    </article>
  );
}

function SourceBadge({ plan }: { plan: RemediationPlanData }) {
  const sourceLabel = {
    anthropic: "CLAUDE",
    openai: "OPENAI",
    scanner_template: "PLANO-BASE",
  }[plan.source];

  return (
    <small className={`ai-source ai-source--${plan.source}`}>
      {sourceLabel}{plan.cached ? " · SALVO" : ""}
    </small>
  );
}

function PlanMetadata({ plan }: { plan: RemediationPlanData }) {
  if (plan.source === "scanner_template") {
    return (
      <div className="ai-plan__metadata">
        <span>Sem consumo de tokens</span>
        <span>Gerado a partir dos dados do scanner</span>
      </div>
    );
  }

  return (
    <div className="ai-plan__metadata" aria-label="Metadados da geração">
      <span>Versão {plan.version ?? 1}</span>
      <span>{plan.model}</span>
      {plan.generated_at && <span>{formatDate(plan.generated_at)}</span>}
      <span>{formatTokens(plan.total_tokens)} tokens</span>
      <span>Custo estimado: {formatUsd(plan.estimated_cost_usd)}</span>
      {plan.previous_versions > 0 && (
        <span>{plan.previous_versions} versão(ões) anterior(es) preservada(s)</span>
      )}
    </div>
  );
}

function PlanList({
  title,
  items,
  numbered = false,
}: {
  title: string;
  items: string[];
  numbered?: boolean;
}) {
  const List = numbered ? "ol" : "ul";
  return (
    <section className="ai-plan__section">
      <h3>{title}</h3>
      <List>{items.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}</List>
    </section>
  );
}

function OfficialReferences({ references }: { references: string[] }) {
  return (
    <details className="ai-plan__references">
      <summary>FONTES OFICIAIS PARA CONFERÊNCIA ({references.length})</summary>
      <ul>
        {references.map((reference) => (
          <li key={reference}>
            <a href={reference} rel="noreferrer" target="_blank">
              {referenceLabel(reference)}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}

function referenceLabel(reference: string) {
  let url: URL;
  try {
    url = new URL(reference);
  } catch {
    return "Referência oficial";
  }
  const cve = url.pathname.match(/CVE-\d{4}-\d{4,}/i)?.[0];
  const nessusPlugin = url.pathname.match(/\/nessus\/(\d+)/)?.[1];
  const rockyAdvisory = url.pathname.match(/\/(RLSA-\d{4}:\d+)/i)?.[1];

  if (nessusPlugin) return `Tenable — plugin ${nessusPlugin}`;
  if (rockyAdvisory) return `Rocky Linux — ${rockyAdvisory.toUpperCase()}`;
  if (url.hostname === "grafana.com" && url.pathname.includes("security-advisories")) {
    return cve ? `Grafana Labs — ${cve.toUpperCase()}` : "Grafana Labs — security advisories";
  }
  if (cve) return `NVD — ${cve.toUpperCase()}`;
  if (url.hostname === "grafana.com") return "Grafana Labs — guia de atualização";
  if (url.hostname === "csrc.nist.gov") return "NIST — diretrizes para TLS";
  if (url.hostname === "docs.redhat.com") return "Red Hat — documentação técnica";
  if (url.hostname === "docs.rockylinux.org") return "Rocky Linux — documentação técnica";
  return url.hostname;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}

function formatTokens(value: number | null) {
  return new Intl.NumberFormat("pt-BR").format(value ?? 0);
}

function formatUsd(value: number | null) {
  return new Intl.NumberFormat("pt-BR", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 4,
    maximumFractionDigits: 6,
  }).format(value ?? 0);
}
