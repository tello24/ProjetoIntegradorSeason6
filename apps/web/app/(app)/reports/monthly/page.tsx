import type { Metadata } from "next";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { MetricCard } from "@/components/metric-card";
import { PageTitle } from "@/components/page-title";
import { ReportActions } from "@/components/report-actions";
import { serverApi } from "@/lib/api-server";

import styles from "./monthly-report.module.css";

export const metadata: Metadata = {
  title: "Evolução mensal",
};

const PERIOD_OPTIONS = [6, 12, 18, 24] as const;
const SEVERITY_OPTIONS = ["critical", "high", "medium", "low"] as const;

type Severity = (typeof SEVERITY_OPTIONS)[number];

interface MonthlyReportPoint {
  month: string;
  scans: number;
  new_findings: number;
  resolved_findings: number;
  reopened_findings: number;
  net_change: number;
  backlog: number;
}

interface MonthlyReport {
  months: number;
  severity: Severity | null;
  summary: {
    period_start: string;
    period_end: string;
    scans: number;
    months_with_scans: number;
    new_findings: number;
    resolved_findings: number;
    reopened_findings: number;
    net_change: number;
    current_backlog: number;
    correction_ratio: number | null;
  };
  timeline: MonthlyReportPoint[];
}

interface MonthlyReportPageProps {
  searchParams: Promise<{
    months?: string | string[];
    severity?: string | string[];
  }>;
}

export default async function MonthlyReportPage({ searchParams }: MonthlyReportPageProps) {
  const requested = await searchParams;
  const months = parseMonths(singleValue(requested.months));
  const severity = parseSeverity(singleValue(requested.severity));
  const query = new URLSearchParams({ months: String(months) });
  if (severity) {
    query.set("severity", severity);
  }
  const report = await serverApi<MonthlyReport>(`/reports/monthly?${query.toString()}`);
  const hasData = report.summary.scans > 0 || report.summary.new_findings > 0;
  const maxMovement = Math.max(
    1,
    ...report.timeline.flatMap((point) => [
      point.new_findings,
      point.resolved_findings,
      point.reopened_findings,
    ]),
  );

  return (
    <div className={`page-content ${styles.reportPage}`}>
      <PageTitle
        eyebrow="RELATÓRIOS / EVOLUÇÃO"
        title="Comparativo mensal"
        description="Entradas, correções e comportamento do backlog ao longo do tempo."
        action={<ReportActions months={months} severity={severity ?? ""} />}
      />

      <section className={styles.filtersPanel} aria-label="Filtros do relatório">
        <form className={styles.filters} method="get">
          <label>
            <span>PERÍODO</span>
            <select defaultValue={months} name="months">
              {PERIOD_OPTIONS.map((option) => (
                <option key={option} value={option}>Últimos {option} meses</option>
              ))}
            </select>
          </label>
          <label>
            <span>SEVERIDADE</span>
            <select defaultValue={severity ?? ""} name="severity">
              <option value="">Todas as severidades</option>
              <option value="critical">Crítica</option>
              <option value="high">Alta</option>
              <option value="medium">Média</option>
              <option value="low">Baixa</option>
            </select>
          </label>
          <button className="button button--primary" type="submit">Aplicar filtros</button>
        </form>
        <div className={styles.coverage}>
          <Icon name="calendar" size={18} />
          <p>
            <strong>{report.summary.scans} scans analisados</strong>
            <span>
              Dados em {report.summary.months_with_scans} de {report.months} meses do período
            </span>
          </p>
        </div>
      </section>

      <section className="metrics-grid" aria-label="Resumo do período">
        <MetricCard
          helper="Primeira detecção dentro do período"
          icon={<Icon name="vulnerability" size={19} />}
          label="NOVAS VULNERABILIDADES"
          tone="cyan"
          value={report.summary.new_findings}
        />
        <MetricCard
          helper="Ausentes em um scan equivalente posterior"
          icon={<Icon name="shield" size={19} />}
          label="VULNERABILIDADES CORRIGIDAS"
          tone="green"
          value={report.summary.resolved_findings}
        />
        <MetricCard
          helper="Voltaram após uma correção confirmada"
          icon={<Icon name="vulnerability" size={19} />}
          label="REABERTAS"
          tone="red"
          value={report.summary.reopened_findings}
        />
        <MetricCard
          helper="Achados ainda ativos no encerramento do mês"
          icon={<Icon name="report" size={19} />}
          label="BACKLOG ATUAL"
          tone="blue"
          value={report.summary.current_backlog}
        />
      </section>

      {hasData ? (
        <section className={styles.reportGrid}>
          <article className={`panel ${styles.movementPanel}`}>
            <div className="panel__heading">
              <div>
                <h2>Novas × corrigidas</h2>
                <p>Movimentações confirmadas em cada mês</p>
              </div>
              <div className={styles.legend} aria-label="Legenda">
                <span className={styles.legendNew}>Novas</span>
                <span className={styles.legendResolved}>Corrigidas</span>
                <span className={styles.legendReopened}>Reabertas</span>
              </div>
            </div>
            <div className={styles.barChart}>
              {report.timeline.map((point) => (
                <div
                  className={`${styles.monthGroup}${point.scans === 0 ? ` ${styles.noScan}` : ""}`}
                  key={point.month}
                  title={monthTooltip(point)}
                >
                  <div className={styles.bars}>
                    <ReportBar
                      max={maxMovement}
                      tone="new"
                      value={point.new_findings}
                    />
                    <ReportBar
                      max={maxMovement}
                      tone="resolved"
                      value={point.resolved_findings}
                    />
                    <ReportBar
                      max={maxMovement}
                      tone="reopened"
                      value={point.reopened_findings}
                    />
                  </div>
                  <strong>{formatMonth(point.month)}</strong>
                  <small>{point.scans > 0 ? scanLabel(point.scans) : "sem scan"}</small>
                </div>
              ))}
            </div>
          </article>

          <article className={`panel ${styles.balancePanel}`}>
            <div className="panel__heading">
              <div>
                <h2>Leitura do período</h2>
                <p>Resumo da capacidade de correção</p>
              </div>
            </div>
            <div className={styles.balanceBody}>
              <span className={styles.balanceLabel}>SALDO LÍQUIDO</span>
              <strong className={report.summary.net_change <= 0 ? styles.positive : styles.negative}>
                {signedNumber(report.summary.net_change)}
              </strong>
              <p>
                {balanceMessage(report.summary.net_change)}
              </p>
              <div className={styles.ratio}>
                <span>Relação entre correções e entradas</span>
                <strong>
                  {report.summary.correction_ratio == null
                    ? "Sem movimentações"
                    : `${report.summary.correction_ratio.toFixed(1)}%`}
                </strong>
              </div>
            </div>
          </article>

          <article className={`panel ${styles.backlogPanel}`}>
            <div className="panel__heading">
              <div>
                <h2>Evolução do backlog</h2>
                <p>Achados que permaneciam ativos ao final de cada mês</p>
              </div>
              <span className="panel__tag">HISTÓRICO</span>
            </div>
            <BacklogChart points={report.timeline} />
          </article>

          <article className={`panel ${styles.tablePanel}`}>
            <div className="panel__heading">
              <div>
                <h2>Detalhamento mensal</h2>
                <p>Números exatos utilizados nos gráficos</p>
              </div>
            </div>
            <div className={styles.tableScroll}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Mês</th>
                    <th>Cobertura</th>
                    <th>Novas</th>
                    <th>Corrigidas</th>
                    <th>Reabertas</th>
                    <th>Saldo</th>
                    <th>Backlog</th>
                  </tr>
                </thead>
                <tbody>
                  {report.timeline.map((point) => (
                    <tr key={point.month}>
                      <td><strong>{formatLongMonth(point.month)}</strong></td>
                      <td>
                        <span className={point.scans > 0 ? styles.scanBadge : styles.noScanBadge}>
                          {point.scans > 0 ? scanLabel(point.scans) : "Sem scan"}
                        </span>
                      </td>
                      <td>{point.new_findings}</td>
                      <td className={styles.resolvedCell}>{point.resolved_findings}</td>
                      <td className={styles.reopenedCell}>{point.reopened_findings}</td>
                      <td className={point.net_change <= 0 ? styles.positiveCell : styles.negativeCell}>
                        {signedNumber(point.net_change)}
                      </td>
                      <td>{point.backlog}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>

          <MetricDefinitions />
        </section>
      ) : (
        <article className="panel">
          <EmptyState
            description="Importe um arquivo .nessus para começar a construir o comparativo mensal. Meses sem scan serão identificados, nunca tratados como ausência de vulnerabilidades."
            icon={<Icon name="report" size={25} />}
            title="Ainda não existe histórico para comparar"
          />
        </article>
      )}
    </div>
  );
}

function ReportBar({ max, tone, value }: { max: number; tone: string; value: number }) {
  const height = value > 0 ? Math.max((value / max) * 100, 5) : 0;
  return (
    <span
      aria-label={`${value} ${tone}`}
      className={`${styles.bar} ${styles[`bar_${tone}`]}`}
      style={{ height: `${height}%` }}
    >
      {value > 0 && <i>{value}</i>}
    </span>
  );
}

function BacklogChart({ points }: { points: MonthlyReportPoint[] }) {
  const width = 1000;
  const top = 28;
  const bottom = 166;
  const left = 45;
  const right = 970;
  const max = Math.max(1, ...points.map((point) => point.backlog));
  const step = points.length > 1 ? (right - left) / (points.length - 1) : 0;
  const coordinates = points.map((point, index) => ({
    point,
    x: left + step * index,
    y: bottom - (point.backlog / max) * (bottom - top),
  }));
  const line = coordinates.map(({ x, y }) => `${x},${y}`).join(" ");
  const area = `${left},${bottom} ${line} ${right},${bottom}`;
  const labelStep = points.length > 12 ? 2 : 1;

  return (
    <div className={styles.lineChart}>
      <svg
        aria-label="Linha de evolução do backlog mensal"
        preserveAspectRatio="none"
        role="img"
        viewBox={`0 0 ${width} 210`}
      >
        <defs>
          <linearGradient id="backlog-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="#4388ff" stopOpacity="0.3" />
            <stop offset="1" stopColor="#4388ff" stopOpacity="0" />
          </linearGradient>
        </defs>
        <line className={styles.gridLine} x1={left} x2={right} y1={top} y2={top} />
        <line className={styles.gridLine} x1={left} x2={right} y1={bottom} y2={bottom} />
        <polygon fill="url(#backlog-area)" points={area} />
        <polyline className={styles.backlogLine} points={line} />
        {coordinates.map(({ point, x, y }, index) => (
          <g key={point.month}>
            <circle
              className={point.scans > 0 ? styles.backlogPoint : styles.backlogPointMuted}
              cx={x}
              cy={y}
              r="5"
            />
            <text className={styles.pointValue} textAnchor="middle" x={x} y={y - 13}>
              {point.backlog}
            </text>
            {index % labelStep === 0 && (
              <text className={styles.monthLabel} textAnchor="middle" x={x} y="196">
                {formatMonth(point.month)}
              </text>
            )}
          </g>
        ))}
      </svg>
    </div>
  );
}

function MetricDefinitions() {
  return (
    <article className={`panel ${styles.definitions}`}>
      <div className={styles.definitionHeading}>
        <span>i</span>
        <div>
          <h2>Como os números são calculados</h2>
          <p>O relatório considera apenas comparações entre scans do mesmo escopo.</p>
        </div>
      </div>
      <dl>
        <div><dt>Nova</dt><dd>Primeira aparição da vulnerabilidade no ambiente.</dd></div>
        <div><dt>Corrigida</dt><dd>Deixou de aparecer no scan seguinte do mesmo escopo.</dd></div>
        <div><dt>Reaberta</dt><dd>Voltou a aparecer depois de uma correção confirmada.</dd></div>
        <div><dt>Backlog</dt><dd>Total que permanecia ativo ao encerramento do mês.</dd></div>
      </dl>
    </article>
  );
}

function singleValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function parseMonths(value: string | undefined) {
  const parsed = Number(value);
  return PERIOD_OPTIONS.includes(parsed as (typeof PERIOD_OPTIONS)[number]) ? parsed : 12;
}

function parseSeverity(value: string | undefined): Severity | null {
  return SEVERITY_OPTIONS.includes(value as Severity) ? (value as Severity) : null;
}

function asLocalDate(value: string) {
  return new Date(`${value.slice(0, 10)}T12:00:00`);
}

function formatMonth(value: string) {
  return new Intl.DateTimeFormat("pt-BR", { month: "short", year: "2-digit" })
    .format(asLocalDate(value))
    .replace(" de ", "/")
    .replace(".", "");
}

function formatLongMonth(value: string) {
  const formatted = new Intl.DateTimeFormat("pt-BR", { month: "long", year: "numeric" })
    .format(asLocalDate(value));
  return formatted.charAt(0).toUpperCase() + formatted.slice(1);
}

function scanLabel(scans: number) {
  return `${scans} ${scans === 1 ? "scan" : "scans"}`;
}

function signedNumber(value: number) {
  return value > 0 ? `+${value}` : String(value);
}

function balanceMessage(value: number) {
  if (value < 0) return "O ambiente encerrou mais vulnerabilidades do que recebeu no período.";
  if (value === 0) return "As correções acompanharam exatamente as entradas do período.";
  return "Entraram mais vulnerabilidades do que foram corrigidas no período.";
}

function monthTooltip(point: MonthlyReportPoint) {
  return `${formatLongMonth(point.month)}: ${point.new_findings} novas, ${point.resolved_findings} corrigidas, ${point.reopened_findings} reabertas.`;
}
