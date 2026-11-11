import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { getSummary, listAlerts, runAnalysis } from "../api/client";
import type { AlertStatus, Severity } from "../api/types";
import { KpiCards } from "../components/KpiCards";
import { RiskBar, SeverityPill } from "../components/Pills";
import { useAuth } from "../auth";
import { STATUS_LABEL, SEVERITY_LABEL, timeAgo } from "../lib/format";

const PAGE_SIZE = 10;

export function AlertsPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<AlertStatus | "">("open");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [offset, setOffset] = useState(0);

  const summary = useQuery({ queryKey: ["summary"], queryFn: getSummary });
  const alerts = useQuery({
    queryKey: ["alerts", { status, severity, offset }],
    queryFn: () => listAlerts({ status: status || undefined, severity: severity || undefined, limit: PAGE_SIZE, offset }),
    placeholderData: (prev) => prev,
  });

  const analysis = useMutation({
    mutationFn: runAnalysis,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["summary"] });
    },
  });

  const page = alerts.data;
  const from = page && page.total > 0 ? page.offset + 1 : 0;
  const to = page ? page.offset + page.items.length : 0;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="muted">Findings are potentially suspicious, never confirmed attacks.</p>
        </div>
        {can("analyst", "admin") ? (
          <button className="btn btn-primary" type="button" disabled={analysis.isPending} onClick={() => analysis.mutate()}>
            {analysis.isPending ? "Analyzing…" : "Run analysis"}
          </button>
        ) : null}
      </header>

      {analysis.isSuccess ? (
        <div className="alert-banner" role="status">
          Scanned {analysis.data.events_scanned} events, {analysis.data.alerts_created} new alerts
          {analysis.data.anomaly_model ? ` (rules + ${analysis.data.anomaly_model})` : " (rules only)"}.
        </div>
      ) : null}
      {analysis.isError ? <div className="alert-banner error" role="alert">{analysis.error.message}</div> : null}

      {summary.data ? <KpiCards summary={summary.data} /> : null}
      {summary.isError ? <div className="alert-banner error" role="alert">Could not load the summary: {summary.error.message}</div> : null}

      <section className="card" aria-label="Alert queue">
        <div className="card-head">
          <h2 style={{ fontSize: 15, fontWeight: 600 }}>
            Alert queue <span className="muted" style={{ fontWeight: 400 }}>· highest risk first</span>
          </h2>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <label>
              <span className="sr-only">Status</span>
              <select className="select" value={status} onChange={(e) => { setStatus(e.target.value as AlertStatus | ""); setOffset(0); }}>
                <option value="">Status: all</option>
                {(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
              </select>
            </label>
            <label>
              <span className="sr-only">Severity</span>
              <select className="select" value={severity} onChange={(e) => { setSeverity(e.target.value as Severity | ""); setOffset(0); }}>
                <option value="">Severity: all</option>
                {(Object.keys(SEVERITY_LABEL) as Severity[]).map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
              </select>
            </label>
          </div>
        </div>

        {alerts.isPending ? (
          <div className="state" role="status">Loading alerts&hellip;</div>
        ) : alerts.isError ? (
          <div className="state" role="alert">
            <span>Could not load alerts: {alerts.error.message}</span>
            <button className="btn btn-sm" type="button" onClick={() => void alerts.refetch()}>Try again</button>
          </div>
        ) : page && page.items.length === 0 ? (
          <div className="state">
            <strong style={{ color: "var(--text)" }}>No alerts match these filters</strong>
            <span>Try widening the filters{can("analyst", "admin") ? ", or run analysis on newly ingested events" : ""}.</span>
          </div>
        ) : page ? (
          <div className="table-wrap">
            <div className="table-head th" role="row">
              <span>Severity</span><span>Alert</span><span>Source</span><span>Risk</span><span style={{ textAlign: "right" }}>Age</span>
            </div>
            {page.items.map((a) => (
              <Link key={a.id} className="row" to={`/alerts/${a.id}`}>
                <SeverityPill severity={a.severity} />
                <div style={{ minWidth: 0 }}>
                  <div className="row-title">{a.title}</div>
                  <div className="mono muted" style={{ fontSize: 12, marginTop: 2 }}>{a.rule_id} · {a.evidence_count} events</div>
                </div>
                <span className="mono">{a.source_ip ?? "multiple"}</span>
                <RiskBar score={a.risk_score} severity={a.severity} />
                <span className="muted" style={{ textAlign: "right" }}>{timeAgo(a.created_at)}</span>
              </Link>
            ))}
          </div>
        ) : null}

        {page && page.total > 0 ? (
          <div className="card-foot">
            <span>Showing {from}–{to} of {page.total}</span>
            <span style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-sm" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
              <button className="btn btn-sm" type="button" disabled={to >= page.total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button>
            </span>
          </div>
        ) : null}
      </section>
    </>
  );
}
