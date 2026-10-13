import type { ReactNode } from "react";

import { Icon } from "@/components/icons";

interface MetricCardProps {
  label: string;
  value: string | number;
  helper: string;
  tone: "cyan" | "red" | "green" | "blue";
  icon: ReactNode;
  info?: ReactNode;
  infoLabel?: string;
}

export function MetricCard({
  label,
  value,
  helper,
  tone,
  icon,
  info,
  infoLabel = "Como este indicador é calculado",
}: MetricCardProps) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__top">
        <div className="metric-card__label">
          <span>{label}</span>
          {info && (
            <details className="metric-info">
              <summary aria-label={infoLabel} title={infoLabel}>
                <Icon name="info" size={13} />
              </summary>
              <div className="metric-info__panel" role="note">
                <strong>{infoLabel}</strong>
                {info}
              </div>
            </details>
          )}
        </div>
        <span className="metric-card__icon">{icon}</span>
      </div>
      <strong>{value}</strong>
      <p>{helper}</p>
    </article>
  );
}
