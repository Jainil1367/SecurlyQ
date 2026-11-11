import type { AlertSummary, Severity } from "../api/types";
import { SEVERITY_LABEL, formatDuration } from "../lib/format";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function KpiCards({ summary }: { summary: AlertSummary }) {
  const open = summary.by_status.open ?? 0;
  const parts = ORDER.map((s) => ({ s, n: summary.open_by_severity[s] ?? 0 })).filter((p) => p.n > 0);
  const legend = parts.map((p) => `${p.n} ${SEVERITY_LABEL[p.s].toLowerCase()}`).join(" · ");
  const mtta = summary.mean_time_to_acknowledge_seconds;

  return (
    <section className="kpis" aria-label="Summary">
      <div className="card kpi">
        <span className="th">Open alerts</span>
        <span className="kpi-value">{open}</span>
        {parts.length > 0 ? (
          <div className="stack-bar" role="img" aria-label={legend}>
            {parts.map((p) => (
              <span key={p.s} className={`fill-${p.s}`} style={{ flex: p.n }} />
            ))}
          </div>
        ) : null}
        <span className="muted">{legend || "Nothing needs attention"}</span>
      </div>
      <div className="card kpi">
        <span className="th">Total alerts</span>
        <span className="kpi-value">{summary.total_alerts}</span>
        <span className="muted">
          {summary.by_status.acknowledged ?? 0} acknowledged · {summary.by_status.false_positive ?? 0} false positive
        </span>
      </div>
      <div className="card kpi">
        <span className="th">Mean time to acknowledge</span>
        <span className="kpi-value" style={mtta === null ? { color: "var(--text-muted)" } : undefined}>
          {formatDuration(mtta)}
        </span>
        <span className="muted">{mtta === null ? "Acknowledge an alert to start tracking" : "Across acknowledged alerts"}</span>
      </div>
      <div className="card kpi">
        <span className="th">Top source IPs</span>
        {summary.top_source_ips.length === 0 ? (
          <span className="muted">No source addresses yet</span>
        ) : (
          summary.top_source_ips.slice(0, 3).map((ip) => (
            <div key={ip.source_ip} className="ip-row">
              <span className="mono" style={{ flex: 1 }}>{ip.source_ip}</span>
              <span className="muted">{ip.alerts}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
