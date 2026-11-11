import type { AlertStatus, Severity } from "../api/types";
import { SEVERITY_LABEL, STATUS_LABEL } from "../lib/format";

export function SeverityPill({ severity }: { severity: Severity }) {
  return <span className={`pill sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}

export function StatusPill({ status }: { status: AlertStatus }) {
  return <span className="pill pill-neutral">{STATUS_LABEL[status]}</span>;
}

export function RiskBar({ score, severity }: { score: number; severity: Severity }) {
  const width = Math.max(0, Math.min(100, score));
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <span style={{ fontWeight: 600, width: 40 }}>{score.toFixed(1)}</span>
      <div className="bar" style={{ flex: 1 }} role="img" aria-label={`Risk ${score.toFixed(1)} out of 100`}>
        <span className={`fill-${severity}`} style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}
