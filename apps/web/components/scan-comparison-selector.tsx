"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useMemo, useState } from "react";

import type { ScanItem } from "@/components/scan-workspace";

interface ScanComparisonSelectorProps {
  scans: ScanItem[];
  currentId: number;
  baselineId: number | null;
}

export function ScanComparisonSelector({
  scans,
  currentId,
  baselineId,
}: ScanComparisonSelectorProps) {
  const router = useRouter();
  const [selectedCurrentId, setSelectedCurrentId] = useState(currentId);
  const selectedCurrent = scans.find((scan) => scan.id === selectedCurrentId) ?? scans[0];
  const compatibleBaselines = useMemo(
    () => scans.filter((scan) => isCompatibleBaseline(scan, selectedCurrent)),
    [scans, selectedCurrent],
  );
  const initialBaselineIsCompatible = compatibleBaselines.some((scan) => scan.id === baselineId);
  const [selectedBaselineId, setSelectedBaselineId] = useState<number | null>(
    initialBaselineIsCompatible ? baselineId : compatibleBaselines[0]?.id ?? null,
  );

  function changeCurrent(value: string) {
    const nextCurrentId = Number(value);
    const nextCurrent = scans.find((scan) => scan.id === nextCurrentId) ?? scans[0];
    const nextBaselines = scans.filter((scan) => isCompatibleBaseline(scan, nextCurrent));
    setSelectedCurrentId(nextCurrentId);
    setSelectedBaselineId(nextBaselines[0]?.id ?? null);
  }

  function submitComparison(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = new URLSearchParams({ current: String(selectedCurrentId) });
    if (selectedBaselineId != null) {
      query.set("baseline", String(selectedBaselineId));
    }
    router.push(`/scan/compare?${query.toString()}`);
  }

  return (
    <form className="scan-comparison-selector" onSubmit={submitComparison}>
      <label>
        <span>SCAN-BASE</span>
        <select
          disabled={compatibleBaselines.length === 0}
          onChange={(event) => setSelectedBaselineId(Number(event.target.value))}
          value={selectedBaselineId ?? ""}
        >
          {compatibleBaselines.length === 0 && (
            <option value="">Nenhum scan anterior compatível</option>
          )}
          {compatibleBaselines.map((scan) => (
            <option key={scan.id} value={scan.id}>
              {scan.name} · {formatShortDate(scan.imported_at)}
            </option>
          ))}
        </select>
      </label>

      <span className="scan-comparison-selector__arrow" aria-hidden="true">→</span>

      <label>
        <span>SCAN ATUAL</span>
        <select onChange={(event) => changeCurrent(event.target.value)} value={selectedCurrentId}>
          {scans.map((scan) => (
            <option key={scan.id} value={scan.id}>
              {scan.name} · {formatShortDate(scan.imported_at)}
            </option>
          ))}
        </select>
      </label>

      <button className="button button--primary" type="submit">
        Gerar comparação
      </button>
    </form>
  );
}

function isCompatibleBaseline(candidate: ScanItem, current: ScanItem) {
  if (candidate.scope_key !== current.scope_key) return false;
  return scanOrder(candidate) < scanOrder(current);
}

function scanOrder(scan: ScanItem) {
  return `${new Date(scan.imported_at).toISOString()}-${String(scan.id).padStart(20, "0")}`;
}

function formatShortDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}
