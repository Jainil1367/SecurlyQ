"""Train, tune, and evaluate the anomaly detector; write the model and a report.

Run from the backend/ folder:
    python -m app.ml.train            # full run (~10 s), writes models/ and ../docs/ml/
    python -m app.ml.train --quick    # smaller data, for smoke tests

The workflow is the standard honest ML loop:
    1. TRAIN split      -> fit the model (no labels used for the Isolation Forest)
    2. VALIDATION split -> choose the alert threshold
    3. TEST split       -> report final numbers ONCE; nothing is tuned on it
Splits are consecutive days with disjoint attacker IPs, so nothing leaks between them.
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import UTC
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.core.config import get_settings
from app.ml.detector import MODEL_VERSION, AnomalyDetector
from app.ml.evaluate import best_threshold, confusion_metrics, incident_recall
from app.ml.features import BUCKET_SECONDS, FEATURES, bucket_of, build_features
from app.ml.simulate import simulate_dataset
from app.models import Event
from app.services.rules import RuleEngine

logger = logging.getLogger("securlyq.train")
REPO_ROOT = Path(__file__).resolve().parents[3]


def label_features(events: pd.DataFrame) -> pd.DataFrame:
    """Feature table plus ground-truth columns: y (0/1), scenario, incident_id."""
    feats = build_features(events)
    ts = pd.to_datetime(events["timestamp"], utc=True)
    epoch = (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().astype("int64")
    attacks = events.assign(bucket=(epoch // BUCKET_SECONDS) * BUCKET_SECONDS)
    attacks = attacks[attacks["is_attack"]]
    truth = (
        attacks.groupby(["source_ip", "bucket"])
        .agg(scenario=("scenario", "first"), incident_id=("incident_id", "first"))
        .reset_index()
    )
    out = feats.merge(truth, on=["source_ip", "bucket"], how="left")
    out["y"] = out["scenario"].notna().astype(int)
    out["incident_id"] = out["incident_id"].fillna(-1).astype(int)
    out["scenario"] = out["scenario"].fillna("")
    return out


def rule_flags(events: pd.DataFrame, labeled: pd.DataFrame) -> np.ndarray:
    """Run the deterministic rule engine and mark every (IP, bucket) it cites as evidence."""
    rows = [
        Event(
            id=i,
            fingerprint=hashlib.sha256(f"{i}".encode()).hexdigest(),
            source="sim",
            event_type="login",
            outcome=r.outcome,
            timestamp=r.timestamp.to_pydatetime().astimezone(UTC),
            source_ip=r.source_ip,
            username=r.username,
            attributes={},
        )
        for i, r in enumerate(events.itertuples(index=False), start=1)
    ]
    findings = RuleEngine.from_settings(get_settings()).run(rows)
    flagged = {(e.source_ip, bucket_of(e.timestamp)) for f in findings for e, _ in f.evidence}
    return np.array([(ip, b) in flagged for ip, b in zip(labeled["source_ip"], labeled["bucket"], strict=True)])


def summarize(name: str, labeled: pd.DataFrame, flagged: np.ndarray, test_days: int) -> dict:
    m = confusion_metrics(labeled["y"].to_numpy(), flagged)
    inc = incident_recall(labeled, flagged)
    return {
        "approach": name,
        **m,
        "false_alerts_per_day": round(m["fp"] / test_days, 2),
        "incident_recall": inc["overall"],
        "incident_recall_by_scenario": inc["by_scenario"],
    }


def run(seed: int = 7, quick: bool = False, model_path: str | None = None, report_dir: Path | None = None) -> dict:
    data = simulate_dataset(seed=seed, quick=quick)
    labeled = {name: label_features(df) for name, df in data.items()}
    test_days = 4 if quick else 14

    detector = AnomalyDetector().fit(labeled["train"])  # unsupervised: labels are NOT used

    val_scores = detector.score(labeled["val"])
    detector.threshold = best_threshold(labeled["val"]["y"].to_numpy(), val_scores)

    test = labeled["test"]
    test_scores = detector.score(test)
    model_flags = test_scores >= detector.threshold
    rules_flags = rule_flags(data["test"], test)

    # Supervised reference point: logistic regression trained WITH labels.
    logreg = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000))
    logreg.fit(labeled["train"][FEATURES], labeled["train"]["y"])
    lr_val = logreg.predict_proba(labeled["val"][FEATURES])[:, 1]
    lr_thr = best_threshold(labeled["val"]["y"].to_numpy(), lr_val, np.linspace(0.05, 0.99, 95))
    lr_scores = logreg.predict_proba(test[FEATURES])[:, 1]

    y = test["y"].to_numpy()
    results = [
        summarize("Rules only", test, rules_flags, test_days),
        summarize("Isolation Forest only", test, model_flags, test_days),
        summarize("Hybrid (rules OR model)", test, rules_flags | model_flags, test_days),
        summarize("Logistic regression (supervised, reference)", test, lr_scores >= lr_thr, test_days),
    ]
    report = {
        "model_version": MODEL_VERSION,
        "seed": seed,
        "quick": quick,
        "sklearn_version": sklearn.__version__,
        "threshold": round(detector.threshold, 4),
        "split": {
            name: {
                "buckets": len(df),
                "attack_buckets": int(df["y"].sum()),
                "attack_share": round(float(df["y"].mean()), 4),
                "incidents": int(df.loc[df["incident_id"] >= 0, "incident_id"].nunique()),
            }
            for name, df in labeled.items()
        },
        "test_days": test_days,
        "model_ranking_quality": {
            "roc_auc": round(float(roc_auc_score(y, test_scores)), 3),
            "pr_auc": round(float(average_precision_score(y, test_scores)), 3),
            "pr_auc_baseline_always_positive": round(float(y.mean()), 3),
            "logreg_roc_auc": round(float(roc_auc_score(y, lr_scores)), 3),
            "logreg_pr_auc": round(float(average_precision_score(y, lr_scores)), 3),
        },
        "results": results,
    }

    if model_path:
        detector.metadata["threshold_chosen_on"] = "validation split (max F1)"
        report["model_sha256"] = detector.save(model_path)
        logger.info("model saved to %s", model_path)
    if report_dir:
        write_report(report, report_dir, y, test_scores, lr_scores)
    return report


# ------------------------------------------------------------------------ reporting


def write_report(report: dict, out_dir: Path, y: np.ndarray, model_scores: np.ndarray, lr_scores: np.ndarray) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")

    figure_note = ""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(6, 4), dpi=140)
        for label, scores in [("Isolation Forest (unsupervised)", model_scores), ("Logistic regression (supervised)", lr_scores)]:
            p, r, _ = precision_recall_curve(y, scores)
            ax.plot(r, p, label=label, linewidth=2)
        ax.axhline(float(y.mean()), color="grey", linestyle=":", label="Chance (attack share)")
        ax.set(xlabel="Recall", ylabel="Precision", title="Precision-recall on held-out test split", ylim=(0, 1.02), xlim=(0, 1))
        ax.legend(loc="lower left", fontsize=8)
        ax.grid(alpha=0.3)
        fig.tight_layout()
        fig.savefig(out_dir / "pr_curve.png")
        plt.close(fig)
        figure_note = "\n![Precision-recall curve](pr_curve.png)\n"
    except ImportError:  # matplotlib is optional
        logger.warning("matplotlib not installed; skipping chart")

    lines = [
        "# Anomaly detection evaluation",
        "",
        "> Generated by `python -m app.ml.train`. **Synthetic data**: these numbers compare approaches on simulated",
        "> traffic we generated ourselves. They do **not** establish real-world detection accuracy.",
        "",
        (
            f"Model: `{report['model_version']}` | seed `{report['seed']}` | alert threshold "
            f"`{report['threshold']}` (chosen on the validation split, never on test)."
        ),
        "",
        "## Data splits (chronological, disjoint attacker IPs)",
        "",
        "| Split | Buckets | Attack buckets | Attack share | Attack incidents |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, s in report["split"].items():
        lines.append(f"| {name} | {s['buckets']} | {s['attack_buckets']} | {s['attack_share']:.1%} | {s['incidents']} |")
    lines += [
        "",
        "## Test-split results",
        "",
        "Bucket level = each (IP, 10-minute window). Incident recall = share of attacks flagged at least once.",
        "",
        "| Approach | Precision | Recall | F1 | FPR | False alerts / day | Incident recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in report["results"]:
        lines.append(
            f"| {r['approach']} | {r['precision']:.2f} | {r['recall']:.2f} | {r['f1']:.2f} | {r['fpr']:.3f} "
            f"| {r['false_alerts_per_day']} | {r['incident_recall']:.2f} |"
        )
    q = report["model_ranking_quality"]
    lines += [
        "",
        (
            f"Ranking quality of the Isolation Forest score: ROC-AUC **{q['roc_auc']}**, "
            f"PR-AUC **{q['pr_auc']}** (a useless model would score about {q['pr_auc_baseline_always_positive']})."
        ),
        figure_note,
        "## Incident recall by attack scenario",
        "",
    ]
    scenarios = sorted({s for r in report["results"] for s in r["incident_recall_by_scenario"]})
    lines += ["| Scenario | " + " | ".join(r["approach"].split(" (")[0] for r in report["results"]) + " |", "|---|" + "---:|" * len(report["results"])]
    for s in scenarios:
        cells = []
        for r in report["results"]:
            c = r["incident_recall_by_scenario"].get(s)
            cells.append(f"{c['caught']}/{c['total']}" if c else "-")
        lines.append(f"| {s} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## How to read this honestly",
        "",
        "- Every number is from one seeded simulation; with a few dozen incidents, differences of a few points are noise.",
        "- The rules were written with these attack shapes in mind, so synthetic rule scores are optimistic.",
        "- `low_and_slow` is deliberately stealthy; see which approaches miss it and why.",
        "- Re-running with another `--seed` shows how much the results move.",
        "",
    ]
    (out_dir / "evaluation.md").write_text("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and evaluate the SecurlyQ anomaly detector.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--quick", action="store_true", help="smaller simulation (smoke test)")
    parser.add_argument("--model-path", default=get_settings().anomaly_model_path)
    parser.add_argument("--report-dir", default=str(REPO_ROOT / "docs" / "ml"))
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level="INFO", format="%(levelname)s %(message)s")
    report = run(
        seed=args.seed,
        quick=args.quick,
        model_path=args.model_path,
        report_dir=None if args.no_report else Path(args.report_dir),
    )
    for r in report["results"]:
        print(f"{r['approach']:<46} P={r['precision']:.2f} R={r['recall']:.2f} F1={r['f1']:.2f} "
              f"FP/day={r['false_alerts_per_day']:<5} incidents={r['incident_recall']:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
