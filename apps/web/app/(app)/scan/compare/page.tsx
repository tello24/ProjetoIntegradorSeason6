import type { Metadata } from "next";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { PageTitle } from "@/components/page-title";
import { ScanComparisonSelector } from "@/components/scan-comparison-selector";
import type { ScanItem } from "@/components/scan-workspace";
import { serverApi } from "@/lib/api-server";

import styles from "./scan-comparison.module.css";

export const metadata: Metadata = {
  title: "Comparador de scans",
};

const CATEGORIES = ["new", "resolved", "reopened", "persistent"] as const;
const SEVERITIES = ["critical", "high", "medium", "low"] as const;

type ComparisonCategory = (typeof CATEGORIES)[number];
type Severity = (typeof SEVERITIES)[number];

interface ScanResponse {
  items: ScanItem[];
  total: number;
}

interface ComparisonFinding {
  finding_id: number;
  category: ComparisonCategory;
  plugin_id: number;
  title: string;
  cves: string[];
  asset: string;
  address: string;
  protocol: string;
  port: number;
  service: string | null;
  severity: Severity;
  severity_before: Severity | null;
  severity_after: Severity | null;
  cvss: number | null;
  neo_score: number;
  neo_score_before: number | null;
  neo_score_after: number | null;
}

interface SeverityComparison {
  severity: Severity;
  new_findings: number;
  reopened_findings: number;
  resolved_findings: number;
  persistent_findings: number;
}

interface AssetChange {
  host_id: number;
  asset: string;
  address: string;
  previous_findings: number;
  current_findings: number;
  previous_risk: number;
  current_risk: number;
  risk_delta: number;
  direction: "improved" | "worsened" | "stable";
}

interface ScanComparison {
  current_scan_id: number;
  current_scan_name: string;
  current_imported_at: string;
  previous_scan_id: number | null;
  previous_scan_name: string | null;
  previous_imported_at: string | null;
  current_findings: number;
  previous_findings: number;
  new_findings: number;
  reopened_findings: number;
  resolved_findings: number;
  persistent_findings: number;
  current_risk_score: number;
  previous_risk_score: number;
  risk_delta: number;
  direction: "baseline" | "worsened" | "improved" | "stable";
  assets_improved: number;
  assets_worsened: number;
  assets_stable: number;
  severity_breakdown: SeverityComparison[];
  asset_changes: AssetChange[];
  items: ComparisonFinding[];
  filtered_total: number;
  page: number;
  page_size: number;
}

interface ComparePageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function ScanComparePage({ searchParams }: ComparePageProps) {
  const requested = await searchParams;
  const scanResponse = await serverApi<ScanResponse>("/scans");
  const scans = scanResponse.items.filter((scan) => scan.status === "concluido");

  if (scans.length === 0) {
    return (
      <div className="page-content">
        <PageTitle
          eyebrow="Scans / evolução"
          title="Comparador de scans"
          description="Descubra exatamente o que entrou, permaneceu, voltou ou foi corrigido."
          action={<BackToScans />}
        />
        <section className="panel">
          <EmptyState
            description="Importe ao menos um scan concluído para criar o baseline da comparação."
            icon={<Icon name="scan" size={26} />}
            title="Nenhum scan disponível"
          />
        </section>
      </div>
    );
  }

  const requestedCurrentId = parsePositiveInteger(singleValue(requested.current));
  const currentScan = scans.find((scan) => scan.id === requestedCurrentId) ?? scans[0];
  const compatibleBaselines = scans.filter((scan) => isCompatibleBaseline(scan, currentScan));
  const requestedBaselineId = parsePositiveInteger(singleValue(requested.baseline));
  const baselineScan =
    compatibleBaselines.find((scan) => scan.id === requestedBaselineId)
    ?? compatibleBaselines[0]
    ?? null;
  const category = parseCategory(singleValue(requested.category));
  const severity = parseSeverity(singleValue(requested.severity));
  const search = (singleValue(requested.search) ?? "").trim().slice(0, 120);
  const page = parsePositiveInteger(singleValue(requested.page)) ?? 1;

  const apiQuery = new URLSearchParams({ page: String(page), page_size: "50" });
  if (baselineScan) apiQuery.set("baseline_scan_id", String(baselineScan.id));
  if (category) apiQuery.set("category", category);
  if (severity) apiQuery.set("severity", severity);
  if (search) apiQuery.set("search", search);

  const comparison = await serverApi<ScanComparison>(
    `/scans/${currentScan.id}/comparison?${apiQuery.toString()}`,
  );
  const baseParams: ComparisonParams = {
    current: currentScan.id,
    baseline: comparison.previous_scan_id,
    category,
    severity,
    search,
  };
  const totalPages = Math.max(1, Math.ceil(comparison.filtered_total / comparison.page_size));

  return (
    <div className={`page-content ${styles.comparisonPage}`}>
      <PageTitle
        eyebrow="Scans / evolução"
        title="Comparador de scans"
        description="Descubra exatamente o que entrou, permaneceu, voltou ou foi corrigido."
        action={<BackToScans />}
      />

      <section className={styles.selectorPanel} aria-label="Selecionar scans para comparação">
        <ScanComparisonSelector
          baselineId={comparison.previous_scan_id}
          currentId={currentScan.id}
          key={`${currentScan.id}-${comparison.previous_scan_id ?? "baseline"}`}
          scans={scans}
        />
        <p>
          Só permitimos comparar scans com a mesma cobertura para não chamar um ativo não
          verificado de “corrigido”.
        </p>
      </section>

      <section className={styles.scanPair} aria-label="Período comparado">
        <ScanCard
          date={comparison.previous_imported_at}
          findings={comparison.previous_findings}
          label="SCAN-BASE"
          name={comparison.previous_scan_name ?? "Baseline inicial"}
          score={comparison.previous_risk_score}
        />
        <div className={styles.pairDelta}>
          <span>VARIAÇÃO DO ÍNDICE</span>
          <strong className={deltaClass(comparison.risk_delta, styles)}>
            {signedNumber(comparison.risk_delta)}
          </strong>
          <small>{directionLabel(comparison.direction)}</small>
        </div>
        <ScanCard
          current
          date={comparison.current_imported_at}
          findings={comparison.current_findings}
          label="Scan atual"
          name={comparison.current_scan_name}
          score={comparison.current_risk_score}
        />
      </section>

      <section className={styles.metricsGrid} aria-label="Resumo da comparação">
        <CategoryMetric
          active={category === "new"}
          href={comparisonHref({ ...baseParams, category: category === "new" ? null : "new" })}
          label="Novas"
          note="Nunca observadas antes"
          tone="new"
          value={comparison.new_findings}
        />
        <CategoryMetric
          active={category === "resolved"}
          href={comparisonHref({
            ...baseParams,
            category: category === "resolved" ? null : "resolved",
          })}
          label="Corrigidas"
          note="Sumiram no scan atual"
          tone="resolved"
          value={comparison.resolved_findings}
        />
        <CategoryMetric
          active={category === "reopened"}
          href={comparisonHref({
            ...baseParams,
            category: category === "reopened" ? null : "reopened",
          })}
          label="Reabertas"
          note="Voltaram após ausência"
          tone="reopened"
          value={comparison.reopened_findings}
        />
        <CategoryMetric
          active={category === "persistent"}
          href={comparisonHref({
            ...baseParams,
            category: category === "persistent" ? null : "persistent",
          })}
          label="Persistentes"
          note="Presentes nos dois scans"
          tone="persistent"
          value={comparison.persistent_findings}
        />
      </section>

      <section className={styles.insightGrid}>
        <article className={`panel ${styles.severityPanel}`}>
          <div className="panel__heading">
            <div>
              <h2>Movimentação por severidade</h2>
              <p>Onde o risco realmente mudou entre os scans</p>
            </div>
            <span className="panel__tag">MATRIZ</span>
          </div>
          <div className={styles.severityMatrix}>
            <div className={styles.matrixHeader}>
              <span>Severidade</span><span>Novas</span><span>Corrigidas</span>
              <span>Reabertas</span><span>Persistentes</span>
            </div>
            {comparison.severity_breakdown.map((row) => (
              <div className={styles.matrixRow} key={row.severity}>
                <span className={`severity-badge severity-badge--${row.severity}`}>
                  {severityLabel(row.severity)}
                </span>
                <strong>{row.new_findings}</strong>
                <strong className={styles.resolvedText}>{row.resolved_findings}</strong>
                <strong className={styles.reopenedText}>{row.reopened_findings}</strong>
                <strong>{row.persistent_findings}</strong>
              </div>
            ))}
          </div>
        </article>

        <article className={`panel ${styles.assetSummary}`}>
          <div className="panel__heading">
            <div>
              <h2>Impacto nos ativos</h2>
              <p>Comparação da carga de risco por equipamento</p>
            </div>
          </div>
          <div className={styles.assetSummaryBody}>
            <AssetSummaryNumber label="Melhoraram" tone="improved" value={comparison.assets_improved} />
            <AssetSummaryNumber label="Pioraram" tone="worsened" value={comparison.assets_worsened} />
            <AssetSummaryNumber label="Estáveis" tone="stable" value={comparison.assets_stable} />
          </div>
        </article>
      </section>

      {comparison.asset_changes.length > 0 && (
        <section className={`panel ${styles.assetsPanel}`}>
          <div className="panel__heading">
            <div>
              <h2>Ativos com maior mudança</h2>
              <p>Priorize onde a exposição mais aumentou ou diminuiu</p>
            </div>
            <span className="panel__tag">TOP {comparison.asset_changes.length}</span>
          </div>
          <div className={styles.tableScroll}>
            <table className={styles.assetTable}>
              <thead>
                <tr><th>Ativo</th><th>Vulnerabilidades</th><th>Carga de risco</th><th>Resultado</th></tr>
              </thead>
              <tbody>
                {comparison.asset_changes.map((asset) => (
                  <tr key={asset.host_id}>
                    <td>
                      <Link href={`/assets/${asset.host_id}`}>
                        <strong>{asset.asset}</strong><small>{asset.address}</small>
                      </Link>
                    </td>
                    <td>{asset.previous_findings} → <strong>{asset.current_findings}</strong></td>
                    <td>{asset.previous_risk} → <strong>{asset.current_risk}</strong></td>
                    <td>
                      <span className={`${styles.changeBadge} ${styles[`change_${asset.direction}`]}`}>
                        {assetDirectionLabel(asset.direction)} {signedNumber(asset.risk_delta)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className={`panel ${styles.findingsPanel}`}>
        <div className="panel__heading">
          <div>
            <h2>Detalhamento dos achados</h2>
            <p>{comparison.filtered_total} resultados para os filtros selecionados</p>
          </div>
          <span className="panel__tag">EVIDÊNCIAS</span>
        </div>

        <form className={styles.filters} method="get">
          <input name="current" type="hidden" value={currentScan.id} />
          {comparison.previous_scan_id != null && (
            <input name="baseline" type="hidden" value={comparison.previous_scan_id} />
          )}
          <label className={styles.searchField}>
            <Icon name="search" size={18} />
            <input defaultValue={search} name="search" placeholder="CVE, plugin, ativo ou IP..." />
          </label>
          <select defaultValue={category ?? ""} name="category">
            <option value="">Todas as movimentações</option>
            <option value="new">Novas</option>
            <option value="resolved">Corrigidas</option>
            <option value="reopened">Reabertas</option>
            <option value="persistent">Persistentes</option>
          </select>
          <select defaultValue={severity ?? ""} name="severity">
            <option value="">Todas as severidades</option>
            <option value="critical">Crítica</option>
            <option value="high">Alta</option>
            <option value="medium">Média</option>
            <option value="low">Baixa</option>
          </select>
          <button className="button button--primary" type="submit">Filtrar</button>
          {(category || severity || search) && (
            <Link className="button button--secondary" href={comparisonHref({
              ...baseParams,
              category: null,
              severity: null,
              search: "",
            })}>
              Limpar
            </Link>
          )}
        </form>

        {comparison.items.length > 0 ? (
          <div className={styles.findingList} role="table" aria-label="Achados comparados">
            <div className={styles.findingHeader} role="row">
              <span>Movimento</span><span>Severidade</span><span>Vulnerabilidade</span>
              <span>Ativo</span><span>WVM Score</span><span>Mudança</span>
            </div>
            {comparison.items.map((finding) => (
              <Link
                className={styles.findingRow}
                href={`/vulnerabilities/${finding.finding_id}`}
                key={`${finding.category}-${finding.finding_id}`}
                role="row"
              >
                <span role="cell">
                  <i className={`${styles.categoryBadge} ${styles[`category_${finding.category}`]}`}>
                    {categoryLabel(finding.category)}
                  </i>
                </span>
                <span role="cell" className={`severity-badge severity-badge--${finding.severity}`}>
                  {severityLabel(finding.severity)}
                </span>
                <span className={styles.findingTitle} role="cell">
                  <strong>{finding.title}</strong>
                  <small>
                    Plugin {finding.plugin_id}
                    {finding.cves.length > 0 ? ` · ${finding.cves.slice(0, 2).join(", ")}` : ""}
                  </small>
                </span>
                <span className={styles.findingAsset} role="cell">
                  <strong>{finding.asset}</strong><small>{finding.address}</small>
                </span>
                <span className={styles.scoreChange} role="cell">
                  {scoreTransition(finding)}
                </span>
                <span role="cell">{severityTransition(finding)}</span>
              </Link>
            ))}
          </div>
        ) : (
          <EmptyState
            description="Tente remover algum filtro ou pesquisar por outro ativo, CVE ou plugin."
            icon={<Icon name="search" size={25} />}
            title="Nenhum achado encontrado"
          />
        )}

        {totalPages > 1 && (
          <nav className={styles.pagination} aria-label="Paginação dos achados">
            {comparison.page > 1 ? (
              <Link href={comparisonHref({ ...baseParams, page: comparison.page - 1 })}>← Anterior</Link>
            ) : <span />}
            <strong>Página {comparison.page} de {totalPages}</strong>
            {comparison.page < totalPages ? (
              <Link href={comparisonHref({ ...baseParams, page: comparison.page + 1 })}>Próxima →</Link>
            ) : <span />}
          </nav>
        )}
      </section>
    </div>
  );
}

function BackToScans() {
  return (
    <Link className="button button--secondary" href="/scan">
      <Icon name="scan" size={17} /> Voltar aos scans
    </Link>
  );
}

function ScanCard({
  current = false,
  date,
  findings,
  label,
  name,
  score,
}: {
  current?: boolean;
  date: string | null;
  findings: number;
  label: string;
  name: string;
  score: number;
}) {
  return (
    <article className={`${styles.scanCard}${current ? ` ${styles.scanCardCurrent}` : ""}`}>
      <div>
        <span>{label}</span><strong>{name}</strong>
        <small>{date ? formatDate(date) : "Primeira leitura do escopo"}</small>
      </div>
      <div className={styles.scanCardStats}>
        <p><span>Achados</span><strong>{findings}</strong></p>
        <p><span>Índice</span><strong>{score}</strong></p>
      </div>
    </article>
  );
}

function CategoryMetric({ active, href, label, note, tone, value }: {
  active: boolean;
  href: string;
  label: string;
  note: string;
  tone: ComparisonCategory;
  value: number;
}) {
  return (
    <Link
      className={`${styles.categoryMetric} ${styles[`metric_${tone}`]}${active ? ` ${styles.metricActive}` : ""}`}
      href={href}
    >
      <span>{label}</span><strong>{value}</strong><small>{note}</small>
    </Link>
  );
}

function AssetSummaryNumber({ label, tone, value }: {
  label: string;
  tone: AssetChange["direction"];
  value: number;
}) {
  return (
    <div className={styles[`asset_${tone}`]}>
      <strong>{value}</strong><span>{label}</span>
    </div>
  );
}

interface ComparisonParams {
  current: number;
  baseline: number | null;
  category?: ComparisonCategory | null;
  severity?: Severity | null;
  search?: string;
  page?: number;
}

function comparisonHref(params: ComparisonParams) {
  const query = new URLSearchParams({ current: String(params.current) });
  if (params.baseline != null) query.set("baseline", String(params.baseline));
  if (params.category) query.set("category", params.category);
  if (params.severity) query.set("severity", params.severity);
  if (params.search) query.set("search", params.search);
  if (params.page && params.page > 1) query.set("page", String(params.page));
  return `/scan/compare?${query.toString()}`;
}

function singleValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function parsePositiveInteger(value: string | undefined) {
  if (!value || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseCategory(value: string | undefined): ComparisonCategory | null {
  return CATEGORIES.find((category) => category === value) ?? null;
}

function parseSeverity(value: string | undefined): Severity | null {
  return SEVERITIES.find((severity) => severity === value) ?? null;
}

function isCompatibleBaseline(candidate: ScanItem, current: ScanItem) {
  if (candidate.scope_key !== current.scope_key) return false;
  const candidateOrder = [new Date(candidate.imported_at).getTime(), candidate.id];
  const currentOrder = [new Date(current.imported_at).getTime(), current.id];
  return candidateOrder[0] < currentOrder[0]
    || (candidateOrder[0] === currentOrder[0] && candidateOrder[1] < currentOrder[1]);
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}

function signedNumber(value: number) {
  return value > 0 ? `+${value}` : String(value);
}

function directionLabel(direction: ScanComparison["direction"]) {
  return {
    baseline: "Baseline criado",
    improved: "Evolução positiva",
    worsened: "Risco em atenção",
    stable: "Cenário estável",
  }[direction];
}

function deltaClass(delta: number, stylesheet: typeof styles) {
  if (delta < 0) return stylesheet.deltaImproved;
  if (delta > 0) return stylesheet.deltaWorsened;
  return stylesheet.deltaStable;
}

function severityLabel(severity: Severity) {
  return { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa" }[severity];
}

function categoryLabel(category: ComparisonCategory) {
  return {
    new: "Nova",
    resolved: "Corrigida",
    reopened: "Reaberta",
    persistent: "Persistente",
  }[category];
}

function assetDirectionLabel(direction: AssetChange["direction"]) {
  return { improved: "Melhorou", worsened: "Piorou", stable: "Estável" }[direction];
}

function severityTransition(finding: ComparisonFinding) {
  const before = finding.severity_before ? severityLabel(finding.severity_before) : "—";
  const after = finding.severity_after ? severityLabel(finding.severity_after) : "—";
  return before === after ? "Sem mudança" : `${before} → ${after}`;
}

function scoreTransition(finding: ComparisonFinding) {
  const before = finding.neo_score_before ?? "—";
  const after = finding.neo_score_after ?? "—";
  return before === after ? String(finding.neo_score) : `${before} → ${after}`;
}
