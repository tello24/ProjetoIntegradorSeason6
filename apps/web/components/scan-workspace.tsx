"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { type ChangeEvent, useCallback, useRef, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { PageTitle } from "@/components/page-title";
import { browserApi, readApiError } from "@/lib/api";

export interface ScanItem {
  id: number;
  name: string;
  scanner: string;
  status: string;
  assets: number;
  vulnerabilities: number;
  imported_at: string;
  scope_key: string;
}

export interface ScannerSource {
  key: string;
  display_name: string;
  extensions: string[];
}

interface ImportAccepted {
  id: string;
}

interface ImportStatus {
  id: string;
  scan_id: number | null;
  filename: string;
  status: string;
  assets: number;
  findings: number;
  resolved: number;
  reopened: number;
  message: string | null;
}

export function ScanWorkspace({
  canImport,
  initialScans,
  scannerSources,
}: {
  canImport: boolean;
  initialScans: ScanItem[];
  scannerSources: ScannerSource[];
}) {
  const router = useRouter();
  const fileInput = useRef<HTMLInputElement>(null);
  const [scans, setScans] = useState<ScanItem[]>(initialScans);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [currentImport, setCurrentImport] = useState<ImportStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    try {
      const response = await browserApi("/scans");
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (!response.ok) throw new Error(await readApiError(response));
      const payload = (await response.json()) as { items: ScanItem[]; total: number };
      setScans(payload.items);
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Não foi possível carregar os scans.");
    } finally {
      setIsLoading(false);
    }
  }, [router]);

  async function handleFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !canImport) return;

    setIsUploading(true);
    setError(null);
    setCurrentImport({
      id: "pending",
      scan_id: null,
      filename: file.name,
      status: "enviando",
      assets: 0,
      findings: 0,
      resolved: 0,
      reopened: 0,
      message: null,
    });

    const body = new FormData();
    body.append("file", file);
    try {
      const response = await browserApi("/scans/import", { method: "POST", body });
      if (!response.ok) throw new Error(await readApiError(response));
      const accepted = (await response.json()) as ImportAccepted;
      await monitorImport(accepted.id);
    } catch (uploadError) {
      const message =
        uploadError instanceof Error ? uploadError.message : "Não foi possível importar o scan.";
      setError(message);
      setCurrentImport((current) =>
        current ? { ...current, status: "falhou", message } : current,
      );
    } finally {
      setIsUploading(false);
    }
  }

  async function monitorImport(importId: string) {
    for (let attempt = 0; attempt < 180; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 1000));
      const response = await browserApi(`/scans/imports/${importId}`);
      if (!response.ok) throw new Error(await readApiError(response));
      const statusPayload = (await response.json()) as ImportStatus;
      setCurrentImport(statusPayload);
      if (statusPayload.status === "concluido") {
        await loadScans();
        router.refresh();
        return;
      }
      if (statusPayload.status === "falhou") {
        throw new Error(statusPayload.message ?? "O processamento do scan falhou.");
      }
    }
    throw new Error("O processamento está demorando mais que o esperado.");
  }

  const normalizedSearch = search.toLocaleLowerCase("pt-BR");
  const visibleScans = scans.filter((scan) =>
    scan.name.toLocaleLowerCase("pt-BR").includes(normalizedSearch),
  );
  const acceptedExtensions = scannerSources.flatMap((source) => source.extensions).join(",");

  return (
    <div className="page-content">
      <PageTitle
        eyebrow="COLETA E HISTÓRICO"
        title="Scans"
        description="Importe e acompanhe os resultados dos scanners de vulnerabilidade."
        action={
          <div className="page-title-actions">
            <input
              accept={acceptedExtensions}
              className="sr-only"
              onChange={handleFile}
              ref={fileInput}
              type="file"
              disabled={!canImport}
            />
            <Link className="button button--secondary" href="/scan/compare">
              <Icon name="report" size={17} /> Comparar scans
            </Link>
            <button
              className="button button--primary"
              disabled={isUploading || !canImport}
              onClick={() => fileInput.current?.click()}
              type="button"
            >
              <Icon name="upload" size={17} />
              {isUploading ? "Processando..." : canImport ? "Importar scan" : "Somente consulta"}
            </button>
          </div>
        }
      />

      <div className="scanner-sources" aria-label="Scanners disponíveis para importação">
        <span>FORMATOS ATIVOS</span>
        {scannerSources.map((source) => (
          <strong key={source.key}>
            {source.display_name} ({source.extensions.join(", ")})
          </strong>
        ))}
        <small>A camada de adaptadores está pronta para receber novos scanners.</small>
      </div>

      {currentImport && (
        <div className={`import-banner import-banner--${currentImport.status}`} role="status">
          <span className="import-banner__pulse" />
          <div>
            <strong>{currentImport.filename}</strong>
            <span>{importStatusLabel(currentImport)}</span>
          </div>
        </div>
      )}
      {error && <p className="page-error" role="alert">{error}</p>}

      <section className="panel table-panel">
        <div className="table-toolbar">
          <div className="search-field search-field--small">
            <Icon name="search" size={18} />
            <input
              aria-label="Pesquisar scans"
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Pesquisar scans..."
              type="search"
              value={search}
            />
          </div>
          <span className="table-toolbar__count">
            {scans.length} {scans.length === 1 ? "scan importado" : "scans importados"}
          </span>
        </div>

        <div className="data-table" role="table" aria-label="Histórico de scans">
          <div className="data-table__header data-table__header--scans" role="row">
            <span role="columnheader">NOME DO SCAN</span>
            <span role="columnheader">SCANNER</span>
            <span role="columnheader">STATUS</span>
            <span role="columnheader">ATIVOS</span>
            <span role="columnheader">VULNERABILIDADES</span>
            <span role="columnheader">IMPORTADO EM</span>
            <span role="columnheader">EVOLUÇÃO</span>
          </div>
          {visibleScans.map((scan) => (
            <div className="data-table__row data-table__row--scans" key={scan.id} role="row">
              <strong role="cell">{scan.name}</strong>
              <span role="cell">{scan.scanner.toUpperCase()}</span>
              <span role="cell"><StatusBadge status={scan.status} /></span>
              <span role="cell">{scan.assets}</span>
              <span role="cell">{scan.vulnerabilities}</span>
              <span role="cell">{formatDate(scan.imported_at)}</span>
              <span role="cell">
                {scan.status === "concluido" ? (
                  <Link className="table-action" href={`/scan/compare?current=${scan.id}`}>
                    Comparar
                  </Link>
                ) : (
                  <span className="table-action table-action--disabled">Aguardando</span>
                )}
              </span>
            </div>
          ))}
          {!isLoading && visibleScans.length === 0 && (
            <EmptyState
              description="Envie uma exportação de um scanner compatível para iniciar a análise e alimentar o dashboard."
              icon={<Icon name="scan" size={26} />}
              title={search ? "Nenhum scan encontrado" : "Nenhum scan importado"}
            />
          )}
          {isLoading && <p className="table-loading">Carregando scans...</p>}
        </div>
      </section>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-badge status-badge--${status}`}>{statusLabel(status)}</span>;
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    recebido: "Recebido",
    validando: "Validando",
    processando: "Processando",
    concluido: "Concluído",
    falhou: "Falhou",
  };
  return labels[status] ?? status;
}

function importStatusLabel(currentImport: ImportStatus) {
  if (currentImport.status === "concluido") {
    const lifecycle: string[] = [];
    if (currentImport.resolved > 0) lifecycle.push(`${currentImport.resolved} corrigidas`);
    if (currentImport.reopened > 0) lifecycle.push(`${currentImport.reopened} reabertas`);
    const suffix = lifecycle.length > 0 ? ` · ${lifecycle.join(" · ")}` : "";
    return `${currentImport.assets} ativos e ${currentImport.findings} vulnerabilidades importados${suffix}.`;
  }
  if (currentImport.status === "falhou") {
    return currentImport.message ?? "Falha durante o processamento.";
  }
  if (currentImport.status === "enviando") return "Enviando arquivo com segurança...";
  return `${statusLabel(currentImport.status)} o arquivo...`;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}
