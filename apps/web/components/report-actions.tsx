"use client";

import { useState } from "react";

import { Icon } from "@/components/icons";
import { browserApi } from "@/lib/api";

interface ReportActionsProps {
  months: number;
  severity: string;
}

export function ReportActions({ months, severity }: ReportActionsProps) {
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState("");

  async function downloadCsv() {
    setIsExporting(true);
    setError("");
    const query = new URLSearchParams({ months: String(months) });
    if (severity) {
      query.set("severity", severity);
    }

    try {
      const response = await browserApi(`/reports/monthly.csv?${query.toString()}`);
      if (!response.ok) {
        throw new Error("Não foi possível exportar os dados.");
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `wvm-evolucao-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch {
      setError("A exportação falhou. Tente novamente.");
    } finally {
      setIsExporting(false);
    }
  }

  return (
    <div className="report-actions">
      <button className="button button--secondary" onClick={() => window.print()} type="button">
        <Icon name="report" size={17} /> Salvar PDF
      </button>
      <button
        className="button button--primary"
        disabled={isExporting}
        onClick={downloadCsv}
        type="button"
      >
        <Icon name="download" size={17} /> {isExporting ? "Exportando..." : "Exportar CSV"}
      </button>
      {error && <span className="report-actions__error" role="alert">{error}</span>}
    </div>
  );
}
