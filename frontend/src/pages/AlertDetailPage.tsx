import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { addNote, explainAlert, getAlert, updateStatus } from "../api/client";
import type { AlertDetail, AlertStatus, Evidence } from "../api/types";
import { RiskBar, SeverityPill, StatusPill } from "../components/Pills";
import { useAuth } from "../auth";
import { formatUtcDateTime, formatUtcTime } from "../lib/format";

function Timeline({ evidence }: { evidence: Evidence[] }) {
  // Outcome is shown by shape + color + label, never color alone.
  return (
    <ol className="timeline">
      {evidence.map(({ event, reason }) => {
        const cls = event.outcome === "failure" ? "out-failure" : event.outcome === "success" ? "out-success" : "out-other";
        const glyph = event.outcome === "failure" ? "●" : event.outcome === "success" ? "◆" : "○";
        return (
          <li key={event.id}>
            <span className="mono muted" title={formatUtcDateTime(event.timestamp)}>{formatUtcTime(event.timestamp)}</span>
            <span className={`glyph ${cls}`} aria-hidden="true">{glyph}</span>
            <span>
              {event.event_type} from <span className="mono">{event.source_ip ?? "unknown"}</span>
              {event.username ? <> as <span className="mono">{event.username}</span></> : null}
              <span className="muted" style={{ display: "block", fontSize: 12 }}>{reason}</span>
            </span>
            <span className={cls}>{event.outcome}</span>
          </li>
        );
      })}
    </ol>
  );
}

function ExplanationPanel({ alert, canExplain }: { alert: AlertDetail; canExplain: boolean }) {
  const queryClient = useQueryClient();
  const explain = useMutation({
    mutationFn: (refresh: boolean) => explainAlert(alert.id, refresh),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["alert", alert.id] }),
  });
  const ex = alert.explanation;

  return (
    <section className="card panel" aria-label="Explanation">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <h2 style={{ fontSize: 16, fontWeight: 600 }}>Explanation</h2>
        {ex ? (
          <span className="pill pill-accent">{ex.source === "llm" ? "Amazon Bedrock · validated" : "Template (model unavailable)"}</span>
        ) : null}
      </div>
      {!ex ? (
        <>
          <p className="muted">No explanation yet. Generate a plain-English summary from the evidence.</p>
          {canExplain ? (
            <button className="btn btn-primary" type="button" disabled={explain.isPending} onClick={() => explain.mutate(false)}>
              {explain.isPending ? "Generating…" : "Explain this alert"}
            </button>
          ) : (
            <p className="muted">Ask an analyst to generate one.</p>
          )}
        </>
      ) : (
        <>
          <div><div className="th">Summary</div><p>{ex.summary}</p></div>
          <div><div className="th">Why it was flagged</div><ul className="ul">{ex.why_flagged.map((t) => <li key={t}>{t}</li>)}</ul></div>
          <div><div className="th">Could be benign</div><ul className="ul">{ex.benign_possibilities.map((t) => <li key={t}>{t}</li>)}</ul></div>
          <div><div className="th">First steps</div><ol className="ul">{ex.investigation_steps.map((t) => <li key={t}>{t}</li>)}</ol></div>
          <div><div className="th">Uncertainty</div><p className="muted">{ex.uncertainty}</p></div>
          <p className="muted" style={{ fontSize: 12 }}>{ex.disclaimer}</p>
          {canExplain ? (
            <button className="btn btn-sm" type="button" disabled={explain.isPending} onClick={() => explain.mutate(true)} style={{ alignSelf: "flex-start" }}>
              {explain.isPending ? "Regenerating…" : "Regenerate"}
            </button>
          ) : null}
        </>
      )}
      {explain.isError ? <div className="alert-banner error" role="alert">{explain.error.message}</div> : null}
    </section>
  );
}

export function AlertDetailPage() {
  const params = useParams();
  const id = Number(params.alertId);
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");

  const query = useQuery({ queryKey: ["alert", id], queryFn: () => getAlert(id), enabled: Number.isInteger(id) });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["alert", id] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["summary"] });
  };
  const setStatus = useMutation({ mutationFn: (s: AlertStatus) => updateStatus(id, s), onSuccess: refresh });
  const saveNote = useMutation({
    mutationFn: (text: string) => addNote(id, text),
    onSuccess: () => { setNote(""); refresh(); },
  });

  if (!Number.isInteger(id)) return <div className="state">Invalid alert id.</div>;
  if (query.isPending) return <div className="state" role="status">Loading alert&hellip;</div>;
  if (query.isError) {
    return (
      <div className="state" role="alert">
        <span>{query.error.message}</span>
        <Link to="/alerts">Back to alerts</Link>
      </div>
    );
  }

  const alert = query.data;
  const canAct = can("analyst", "admin");

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (note.trim()) saveNote.mutate(note.trim());
  }

  return (
    <>
      <Link to="/alerts">&larr; Back to alerts</Link>
      <header className="page-head" style={{ alignItems: "flex-start" }}>
        <div style={{ flex: "1 1 520px", minWidth: 0 }}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
            <SeverityPill severity={alert.severity} />
            <StatusPill status={alert.status} />
            <span className="mono pill pill-neutral">{alert.rule_id}</span>
            {alert.source_ip ? <span className="mono pill pill-neutral">{alert.source_ip}</span> : null}
          </div>
          <h1 style={{ fontSize: 26 }}>{alert.title}</h1>
          <p className="muted" style={{ marginTop: 8 }}>
            Created {formatUtcDateTime(alert.created_at)}. Potentially suspicious activity, not a confirmed attack.
          </p>
        </div>
        {canAct ? (
          <div className="actions">
            {alert.status === "open" ? (
              <button className="btn btn-primary" type="button" disabled={setStatus.isPending} onClick={() => setStatus.mutate("acknowledged")}>Acknowledge</button>
            ) : null}
            {alert.status !== "false_positive" ? (
              <button className="btn" type="button" disabled={setStatus.isPending} onClick={() => setStatus.mutate("false_positive")}>False positive</button>
            ) : null}
            {alert.status !== "resolved" ? (
              <button className="btn" type="button" disabled={setStatus.isPending} onClick={() => setStatus.mutate("resolved")}>Resolve</button>
            ) : null}
            {alert.status !== "open" ? (
              <button className="btn" type="button" disabled={setStatus.isPending} onClick={() => setStatus.mutate("open")}>Reopen</button>
            ) : null}
          </div>
        ) : null}
      </header>
      {setStatus.isError ? <div className="alert-banner error" role="alert">{setStatus.error.message}</div> : null}

      <div className="detail-grid">
        <div className="detail-main">
          <section className="card panel" aria-label="Risk">
            <div className="th">Risk score</div>
            <div style={{ fontSize: 44, fontWeight: 700, lineHeight: 1.1, letterSpacing: "-0.02em" }}>{alert.risk_score.toFixed(1)}</div>
            <RiskBar score={alert.risk_score} severity={alert.severity} />
            {alert.anomaly_score !== null ? (
              <p className="muted">Anomaly model score: {alert.anomaly_score.toFixed(2)} (1.00 is the most unusual)</p>
            ) : (
              <p className="muted">Rule-based finding (no anomaly score).</p>
            )}
          </section>

          <section className="card panel" aria-label="Evidence timeline">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <h2 style={{ fontSize: 16, fontWeight: 600 }}>Evidence timeline</h2>
              <span className="muted" style={{ fontSize: 12 }}>UTC · {alert.evidence.length} of {alert.evidence_count} events</span>
            </div>
            {alert.evidence.length === 0 ? <p className="muted">No evidence events are linked to this alert.</p> : <Timeline evidence={alert.evidence} />}
          </section>

          <section className="card panel" aria-label="Investigation notes">
            <h2 style={{ fontSize: 16, fontWeight: 600 }}>Investigation notes</h2>
            {alert.investigation_notes.length === 0 ? <p className="muted">No notes yet. Notes are saved with the alert and visible to your team.</p> : null}
            {alert.investigation_notes.map((n) => (
              <div key={n.id} className="note">
                <p style={{ whiteSpace: "pre-wrap" }}>{n.notes}</p>
                <p className="muted" style={{ fontSize: 12 }}>{n.author_email ?? "unknown"} · {formatUtcDateTime(n.updated_at)}</p>
              </div>
            ))}
            {canAct ? (
              <form onSubmit={onSubmit} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <label className="field">
                  <span className="sr-only">Add a note</span>
                  <textarea className="textarea" placeholder="What did you check? What did you find?" maxLength={5000} value={note} onChange={(e) => setNote(e.target.value)} />
                </label>
                {saveNote.isError ? <div className="alert-banner error" role="alert">{saveNote.error.message}</div> : null}
                <button className="btn" type="submit" style={{ alignSelf: "flex-end" }} disabled={saveNote.isPending || !note.trim()}>Save note</button>
              </form>
            ) : null}
          </section>
        </div>
        <div className="detail-side">
          <ExplanationPanel alert={alert} canExplain={canAct} />
        </div>
      </div>
    </>
  );
}
