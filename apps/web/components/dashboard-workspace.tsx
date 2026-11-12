"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { MetricCard } from "@/components/metric-card";
import { PageTitle } from "@/components/page-title";
import { browserApi, readApiError } from "@/lib/api";

import workflowStyles from "@/app/(app)/dashboard/workflow-overview.module.css";
import styles from "./dashboard-workspace.module.css";

type DashboardMode = "executive" | "operational";
type SeverityFilter = "critical" | "high" | "medium" | "low";
type ReliabilityLevel = "healthy" | "attention" | "critical" | "empty";

interface RiskAsset {
  id: number;
  name: string;
  operating_system: string | null;
  credentialed: boolean;
  vulnerabilities: number;
  critical: number;
  high: number;
  risk_score: number;
}

interface RiskTrendPoint {
  scan_id: number;
  name: string;
  imported_at: string;
  assets: number;
  vulnerabilities: number;
  risk_score: number;
}

interface WorkflowSummary {
  open: number;
  in_triage: number;
  in_progress: number;
  awaiting_validation: number;
  reopened: number;
  accepted_risk: number;
  overdue: number;
  unassigned: number;
  resolved_this_week: number;
  resolved_last_30_days: number;
  reopened_last_30_days: number;
  resolution_rate: number;
  avg_resolution_days: number | null;
  sla_compliance: number | null;
}

interface DashboardScopeOption {
  key: string;
  label: string;
  scanner: string;
  last_scan_at: string;
  assets: number;
}

interface DataReliability {
  level: ReliabilityLevel;
  last_scan_name: string | null;
  last_scan_at: string | null;
  last_scan_age_days: number | null;
  completed_scans: number;
  failed_imports_last_30_days: number;
  total_scopes: number;
  stale_scopes: number;
  current_assets: number;
  credentialed_assets: number;
  uncredentialed_assets: number;
  credentialed_percentage: number;
}

export interface DashboardSummary {
  assets: number;
  open_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolved_this_week: number;
  urgent_findings: number;
  risk_score: number;
  top_assets: RiskAsset[];
  risk_trend: RiskTrendPoint[];
  workflow: WorkflowSummary;
  reliability: DataReliability;
  scope_options: DashboardScopeOption[];
  applied_filters: {
    scope_key: string | null;
    severity: SeverityFilter | null;
  };
  source: "empty" | "database";
}

const severityOptions: Array<{ value: SeverityFilter; label: string }> = [
  { value: "critical", label: "Crítica" },
  { value: "high", label: "Alta" },
  { value: "medium", label: "Média" },
  { value: "low", label: "Baixa" },
];

const reliabilityLabels: Record<ReliabilityLevel, string> = {
  healthy: "Confiável",
  attention: "Exige atenção",
  critical: "Baixa confiança",
  empty: "Sem dados",
};

export function DashboardWorkspace({ initialSummary }: { initialSummary: DashboardSummary }) {
  const [summary, setSummary] = useState(initialSummary);
  const [mode, setMode] = useState<DashboardMode>("executive");
  const [scopeKey, setScopeKey] = useState(initialSummary.applied_filters.scope_key ?? "all");
  const [severity, setSeverity] = useState<SeverityFilter | "all">(
    initialSummary.applied_filters.severity ?? "all",
  );
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const activeRequest = useRef<AbortController | null>(null);

  useEffect(() => () => activeRequest.current?.abort(), []);

  async function applyFilters(
    nextScope: string,
    nextSeverity: SeverityFilter | "all",
  ) {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setScopeKey(nextScope);
    setSeverity(nextSeverity);
    setIsLoading(true);
    setError(null);

    const params = new URLSearchParams();
    if (nextScope !== "all") params.set("scope_key", nextScope);
    if (nextSeverity !== "all") params.set("severity", nextSeverity);

    try {
      const query = params.size > 0 ? `?${params}` : "";
      const response = await browserApi(`/dashboard/summary${query}`, {
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(await readApiError(response));
      setSummary((await response.json()) as DashboardSummary);
    } catch (requestError) {
      if (requestError instanceof DOMException && requestError.name === "AbortError") return;
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Não foi possível atualizar o dashboard.",
      );
    } finally {
      if (activeRequest.current === controller) setIsLoading(false);
    }
  }

  const activeBacklog =
    summary.workflow.open
    + summary.workflow.in_triage
    + summary.workflow.in_progress
    + summary.workflow.awaiting_validation
    + summary.workflow.reopened;
  const selectedScope = summary.scope_options.find((option) => option.key === scopeKey);

  return (
    <div className={`page-content ${isLoading ? styles.loading : ""}`} aria-busy={isLoading}>
      <PageTitle
        eyebrow="Panorama do ambiente"
        title="Dashboard"
        description={
          mode === "executive"
            ? "Risco, exposição e qualidade dos dados para tomada de decisão."
            : "Fluxo de trabalho, gargalos e desempenho da remediação."
        }
        action={
          <div className="page-title-actions">
            <Link className="button button--secondary" href="/reports/monthly">
              <Icon name="calendar" size={17} /> Evolução mensal
            </Link>
            <span className="status-pill">
              <i />
              {summary.source === "database"
                ? `${reliabilityLabels[summary.reliability.level]} · ${lastUpdateLabel(summary.reliability)}`
                : "Aguardando primeiro scan"}
            </span>
          </div>
        }
      />

      <section className={styles.controlBar} aria-label="Controles do dashboard">
        <div className={styles.modeSwitch} role="group" aria-label="Modo do dashboard">
          <button
            aria-pressed={mode === "executive"}
            className={mode === "executive" ? styles.modeActive : ""}
            onClick={() => setMode("executive")}
            type="button"
          >
            <Icon name="dashboard" size={16} />
            Executivo
          </button>
          <button
            aria-pressed={mode === "operational"}
            className={mode === "operational" ? styles.modeActive : ""}
            onClick={() => setMode("operational")}
            type="button"
          >
            <Icon name="queue" size={16} />
            Operacional
          </button>
        </div>

        <div className={styles.globalFilters}>
          <label>
            <span>ESCOPO</span>
            <select
              disabled={isLoading}
              onChange={(event) => void applyFilters(event.target.value, severity)}
              value={scopeKey}
            >
              <option value="all">Todos os escopos</option>
              {summary.scope_options.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.label} · {option.assets} ativos
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>SEVERIDADE</span>
            <select
              disabled={isLoading}
              onChange={(event) => void applyFilters(
                scopeKey,
                event.target.value as SeverityFilter | "all",
              )}
              value={severity}
            >
              <option value="all">Todas as severidades</option>
              {severityOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <button
            className={styles.clearFilters}
            disabled={isLoading || (scopeKey === "all" && severity === "all")}
            onClick={() => void applyFilters("all", "all")}
            type="button"
          >
            Limpar filtros
          </button>
        </div>
      </section>

      {(scopeKey !== "all" || severity !== "all") && (
        <div className={styles.filterContext}>
          Exibindo {selectedScope?.label ?? "todos os escopos"}
          {severity !== "all"
            ? ` · severidade ${severityOptions.find((item) => item.value === severity)?.label.toLowerCase()}`
            : ""}
        </div>
      )}
      {error && <p className="page-error" role="alert">{error}</p>}

      {mode === "executive" ? (
        <ExecutiveDashboard summary={summary} />
      ) : (
        <OperationalDashboard activeBacklog={activeBacklog} summary={summary} />
      )}

      <ReliabilityPanel reliability={summary.reliability} />
    </div>
  );
}

function ExecutiveDashboard({ summary }: { summary: DashboardSummary }) {
  const hasFindings = summary.open_vulnerabilities > 0;
  return (
    <>
      <section className="metrics-grid" aria-label="Indicadores executivos">
        <MetricCard
          featured
          helper="Métrica consolidada do ambiente filtrado"
          icon={<Icon name="shield" size={19} />}
          info={
            <>
              <p>Usamos os achados do scan mais recente de cada escopo selecionado.</p>
              <p>
                Cada crítica vale 10 pontos, alta 5, média 2 e baixa 1. A soma é
                dividida pela quantidade de ativos e limitada a 100.
              </p>
              <small>Os filtros de escopo e severidade também alteram o resultado.</small>
            </>
          }
          infoLabel="Como a pontuação de risco funciona"
          label="Pontuação de risco"
          tone="cyan"
          value={summary.risk_score}
        />
        <MetricCard
          helper="Achados presentes nos scans mais recentes"
          icon={<Icon name="vulnerability" size={19} />}
          label="Vulnerabilidades abertas"
          tone="red"
          value={summary.open_vulnerabilities}
        />
        <MetricCard
          helper="WVM Score 80 ou superior"
          icon={<Icon name="bolt" size={19} />}
          label="Agir agora"
          tone="red"
          value={summary.urgent_findings}
        />
        <MetricCard
          helper="Ativos presentes nos escopos selecionados"
          icon={<Icon name="assets" size={19} />}
          label="Ativos monitorados"
          tone="blue"
          value={summary.assets}
        />
      </section>

      <section className="dashboard-grid">
        <article className="panel panel--wide">
          <div className="panel__heading">
            <div>
              <h2>Vulnerabilidades por severidade</h2>
              <p>Distribuição dos achados no recorte selecionado</p>
            </div>
            <span className="panel__tag">VISÃO ATUAL</span>
          </div>
          {hasFindings ? (
            <div className="severity-chart">
              <SeverityBar
                label="Críticas"
                tone="critical"
                total={summary.open_vulnerabilities}
                value={summary.critical}
              />
              <SeverityBar
                label="Altas"
                tone="high"
                total={summary.open_vulnerabilities}
                value={summary.high}
              />
              <SeverityBar
                label="Médias"
                tone="medium"
                total={summary.open_vulnerabilities}
                value={summary.medium}
              />
              <SeverityBar
                label="Baixas"
                tone="low"
                total={summary.open_vulnerabilities}
                value={summary.low}
              />
            </div>
          ) : (
            <EmptyState
              action={
                <Link className="button button--secondary" href="/scan">
                  <Icon name="upload" size={17} /> Consultar scans
                </Link>
              }
              description="Não existem achados para os filtros escolhidos. Ajuste o recorte ou consulte os scans."
              icon={<Icon name="dashboard" size={25} />}
              title="Nenhum achado neste recorte"
            />
          )}
        </article>

        <TopAssetsPanel assets={summary.top_assets} />

        <article className="panel panel--full">
          <div className="panel__heading">
            <div>
              <h2>Evolução do risco</h2>
              <p>Comparação dos últimos dez scans dentro dos filtros</p>
            </div>
          </div>
          <RiskTrend points={summary.risk_trend} />
        </article>
      </section>
    </>
  );
}

function OperationalDashboard({
  activeBacklog,
  summary,
}: {
  activeBacklog: number;
  summary: DashboardSummary;
}) {
  return (
    <>
      <section className="metrics-grid" aria-label="Indicadores operacionais">
        <MetricCard
          helper="Itens nas etapas ativas da operação"
          icon={<Icon name="queue" size={19} />}
          label="Backlog operacional"
          tone="cyan"
          value={activeBacklog}
        />
        <MetricCard
          helper="Prazo manual ou SLA automático vencido"
          icon={<Icon name="calendar" size={19} />}
          label="Em atraso"
          tone="red"
          value={summary.workflow.overdue}
        />
        <MetricCard
          helper="Tarefas que ainda precisam de um dono"
          icon={<Icon name="users" size={19} />}
          label="Sem responsável"
          tone="red"
          value={summary.workflow.unassigned}
        />
        <MetricCard
          helper="Correções confirmadas por scan nos últimos 30 dias"
          icon={<Icon name="shield" size={19} />}
          label="Resolvidas em 30 dias"
          tone="green"
          value={summary.workflow.resolved_last_30_days}
        />
      </section>

      <section className={styles.operationalGrid}>
        <article className={`panel ${styles.funnelPanel}`}>
          <div className="panel__heading">
            <div>
              <h2>Funil de remediação</h2>
              <p>Onde o estoque atual está parado no processo</p>
            </div>
            <Link className="button button--secondary" href="/remediation">
              Abrir fila
            </Link>
          </div>
          <RemediationFunnel workflow={summary.workflow} />
        </article>

        <article className={`panel ${styles.healthPanel}`}>
          <div className="panel__heading">
            <div>
              <h2>Efetividade da operação</h2>
              <p>Resultado e velocidade do tratamento</p>
            </div>
          </div>
          <div className={styles.healthMetrics}>
            <EffectivenessMetric
              label="Taxa de resolução"
              value={`${summary.workflow.resolution_rate.toFixed(1)}%`}
            />
            <EffectivenessMetric
              label="Tempo médio para corrigir"
              value={summary.workflow.avg_resolution_days == null
                ? "Sem histórico"
                : `${summary.workflow.avg_resolution_days.toFixed(1)} dias`}
            />
            <EffectivenessMetric
              label="Correções dentro do prazo"
              value={summary.workflow.sla_compliance == null
                ? "Sem prazo concluído"
                : `${summary.workflow.sla_compliance.toFixed(1)}%`}
            />
          </div>
          <div className={styles.exceptionGrid}>
            <WorkflowMetric
              label="Reabertas agora"
              tone="orange"
              value={summary.workflow.reopened}
            />
            <WorkflowMetric
              label="Reabertas em 30 dias"
              tone="orange"
              value={summary.workflow.reopened_last_30_days}
            />
            <WorkflowMetric
              label="Risco aceito"
              tone="muted"
              value={summary.workflow.accepted_risk}
            />
            <WorkflowMetric
              label="Aguardando validação"
              tone="green"
              value={summary.workflow.awaiting_validation}
            />
          </div>
        </article>
      </section>
    </>
  );
}

function RemediationFunnel({ workflow }: { workflow: WorkflowSummary }) {
  const stages = [
    { label: "Abertas", value: workflow.open, tone: "open" },
    { label: "Em triagem", value: workflow.in_triage, tone: "triage" },
    { label: "Em correção", value: workflow.in_progress, tone: "progress" },
    { label: "Em validação", value: workflow.awaiting_validation, tone: "validation" },
    { label: "Resolvidas 30d", value: workflow.resolved_last_30_days, tone: "resolved" },
  ];
  const highest = Math.max(...stages.map((stage) => stage.value), 1);
  return (
    <div className={styles.funnel}>
      {stages.map((stage, index) => (
        <div className={`${styles.funnelStage} ${styles[`funnel_${stage.tone}`]}`} key={stage.label}>
          <div className={styles.funnelIdentity}>
            <span>{index + 1}</span>
            <p>{stage.label}</p>
            <strong>{stage.value}</strong>
          </div>
          <div className={styles.funnelTrack}>
            <i style={{ width: `${Math.max(stage.value / highest * 100, stage.value ? 5 : 0)}%` }} />
          </div>
        </div>
      ))}
      <p className={styles.funnelNote}>
        Os números representam o estoque atual; “Resolvidas” considera os últimos 30 dias.
      </p>
    </div>
  );
}

function ReliabilityPanel({ reliability }: { reliability: DataReliability }) {
  const statusCopy = reliabilityMessage(reliability);
  return (
    <article className={`panel ${styles.reliabilityPanel}`}>
      <div className="panel__heading">
        <div>
          <h2>Confiabilidade dos dados</h2>
          <p>Recência, credenciais e saúde das importações</p>
        </div>
        <span className={`${styles.reliabilityBadge} ${styles[`reliability_${reliability.level}`]}`}>
          {reliabilityLabels[reliability.level]}
        </span>
      </div>
      <div className={styles.reliabilityBody}>
        <div className={styles.reliabilityMetrics}>
          <ReliabilityMetric
            detail={reliability.last_scan_name ?? "Importe o primeiro scan"}
            label="Última atualização"
            tone={reliability.last_scan_age_days != null && reliability.last_scan_age_days > 30
              ? "danger"
              : "default"}
            value={lastUpdateLabel(reliability)}
          />
          <ReliabilityMetric
            detail={`${reliability.credentialed_assets} de ${reliability.current_assets} ativos`}
            label="Ativos com scan credenciado"
            progress={reliability.credentialed_percentage}
            tone={reliability.credentialed_percentage < 50 ? "danger" : "good"}
            value={`${reliability.credentialed_percentage.toFixed(1)}%`}
          />
          <ReliabilityMetric
            detail={`${reliability.total_scopes} escopos monitorados`}
            label="Escopos desatualizados"
            tone={reliability.stale_scopes > 0 ? "danger" : "good"}
            value={reliability.stale_scopes}
          />
          <ReliabilityMetric
            detail={`${reliability.completed_scans} scans concluídos no histórico`}
            label="Falhas em 30 dias"
            tone={reliability.failed_imports_last_30_days > 0 ? "danger" : "good"}
            value={reliability.failed_imports_last_30_days}
          />
        </div>
        <div className={`${styles.reliabilityConclusion} ${styles[`conclusion_${reliability.level}`]}`}>
          <Icon name="info" size={18} />
          <div>
            <strong>{statusCopy.title}</strong>
            <p>{statusCopy.description}</p>
            <small>
              Consideramos saudável: scan em até 7 dias, 80% ou mais de ativos credenciados,
              nenhum escopo acima de 30 dias e nenhuma falha recente.
            </small>
          </div>
        </div>
      </div>
    </article>
  );
}

function ReliabilityMetric({
  detail,
  label,
  progress,
  tone,
  value,
}: {
  detail: string;
  label: string;
  progress?: number;
  tone: "default" | "good" | "danger";
  value: string | number;
}) {
  return (
    <div className={`${styles.reliabilityMetric} ${styles[`metric_${tone}`]}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {progress != null && (
        <div className={styles.reliabilityTrack}><i style={{ width: `${progress}%` }} /></div>
      )}
      <small>{detail}</small>
    </div>
  );
}

function TopAssetsPanel({ assets }: { assets: RiskAsset[] }) {
  return (
    <article className="panel">
      <div className="panel__heading">
        <div>
          <h2>Ativos com maior risco</h2>
          <p>Concentração ponderada dos achados filtrados</p>
        </div>
      </div>
      {assets.length > 0 ? (
        <div className="risk-assets">
          {assets.map((asset, index) => (
            <Link className="risk-assets__row" href={`/assets/${asset.id}`} key={asset.id}>
              <span className="risk-assets__position">{index + 1}</span>
              <div className="risk-assets__identity">
                <strong>{asset.name}</strong>
                <small>
                  {asset.operating_system ?? "Sistema não identificado"}
                  {asset.credentialed ? " · scan credenciado" : " · sem credencial"}
                </small>
              </div>
              <div className="risk-assets__counts">
                <strong>{asset.risk_score}</strong>
                <small>{asset.vulnerabilities} achados</small>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <p className="panel__empty-copy">Nenhum ativo vulnerável neste recorte.</p>
      )}
    </article>
  );
}

function RiskTrend({ points }: { points: RiskTrendPoint[] }) {
  if (points.length === 0) {
    return (
      <div className="chart-placeholder" aria-label="Gráfico sem dados">
        <span>O histórico aparecerá após a primeira importação.</span>
      </div>
    );
  }
  return (
    <div className="risk-trend" aria-label="Evolução da pontuação de risco">
      {points.map((point) => (
        <div
          aria-label={`${point.name}: risco ${point.risk_score}, ${point.vulnerabilities} vulnerabilidades`}
          className="risk-trend__point"
          key={point.scan_id}
          title={`${point.name} · ${point.vulnerabilities} achados · ${point.assets} ativos`}
        >
          <strong>{point.risk_score}</strong>
          <div className="risk-trend__track">
            <i style={{ height: `${Math.max(point.risk_score, 3)}%` }} />
          </div>
          <span>{formatShortDate(point.imported_at)}</span>
        </div>
      ))}
    </div>
  );
}

function WorkflowMetric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "green" | "muted" | "orange";
}) {
  return (
    <div className={`${workflowStyles.item} ${workflowStyles[tone]}`}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function EffectivenessMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className={styles.healthMetric}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SeverityBar({
  label,
  value,
  total,
  tone,
}: {
  label: string;
  value: number;
  total: number;
  tone: "critical" | "high" | "medium" | "low";
}) {
  const width = total > 0 ? Math.max(value / total * 100, value > 0 ? 3 : 0) : 0;
  return (
    <div className={`severity-chart__item severity-chart__item--${tone}`}>
      <div><span>{label}</span><strong>{value}</strong></div>
      <div className="severity-chart__track"><i style={{ width: `${width}%` }} /></div>
    </div>
  );
}

function reliabilityMessage(reliability: DataReliability) {
  if (reliability.level === "empty") {
    return {
      title: "Ainda não é possível avaliar o ambiente.",
      description: "Importe um scan para iniciar a medição de recência e qualidade.",
    };
  }
  if (reliability.level === "healthy") {
    return {
      title: "Os indicadores possuem uma base recente e consistente.",
      description: "A cobertura credenciada e a saúde das importações estão dentro dos critérios.",
    };
  }
  if (reliability.level === "attention") {
    return {
      title: "Use os indicadores com atenção.",
      description: "Existe pelo menos um sinal de recência, credencial ou importação a revisar.",
    };
  }
  return {
    title: "Os números podem não representar o ambiente atual.",
    description: "Priorize um novo scan credenciado e verifique falhas ou escopos desatualizados.",
  };
}

function lastUpdateLabel(reliability: DataReliability) {
  if (reliability.last_scan_age_days == null) return "Sem scan";
  if (reliability.last_scan_age_days === 0) return "Hoje";
  if (reliability.last_scan_age_days === 1) return "Há 1 dia";
  return `Há ${reliability.last_scan_age_days} dias`;
}

function formatShortDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    day: "2-digit",
    month: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}
