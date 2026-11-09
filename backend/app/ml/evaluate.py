"""Evaluation metrics.

Quant lesson: with ~4% attacks, **accuracy is a trap**. A model that never raises an alert
is 96% "accurate". We report:

    precision  of the alerts we raised, how many were real?        TP / (TP + FP)
    recall     of the real attacks, how many did we catch?         TP / (TP + FN)
    FPR        of the normal buckets, how many raised a false alarm? FP / (FP + TN)
    F1         one number balancing precision and recall

Two levels, because analysts think in incidents, not buckets:
    bucket level    each (IP, 10-min) row is one prediction
    incident level  an attack counts as "caught" if ANY of its buckets was flagged
"""

import numpy as np
import pandas as pd


def confusion_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    y_true, y_pred = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    tp = int((y_true & y_pred).sum())
    fp = int((~y_true & y_pred).sum())
    fn = int((y_true & ~y_pred).sum())
    tn = int((~y_true & ~y_pred).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "fpr": round(fpr, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def best_threshold(y_true: np.ndarray, scores: np.ndarray, candidates: np.ndarray | None = None) -> float:
    """Pick the score cutoff with the best F1 on *validation* data (never on test data)."""
    if candidates is None:
        candidates = np.unique(np.round(np.concatenate([np.linspace(0.80, 0.999, 120), np.quantile(scores, [0.95, 0.97, 0.98, 0.99])]), 4))
    best, best_f1 = float(candidates[0]), -1.0
    for t in candidates:
        f1 = confusion_metrics(y_true, scores >= t)["f1"]
        if f1 > best_f1 or (f1 == best_f1 and t > best):  # on ties prefer fewer alerts
            best, best_f1 = float(t), f1
    return best


def incident_recall(labeled: pd.DataFrame, flagged: np.ndarray) -> dict:
    """`labeled` has columns incident_id (>=0 for attacks) and scenario; `flagged` is a bool array.

    Returns overall and per-scenario share of incidents with at least one flagged bucket.
    """
    df = labeled.assign(flagged=np.asarray(flagged, dtype=bool))
    attacks = df[df["incident_id"] >= 0]
    if attacks.empty:
        return {"overall": 0.0, "n_incidents": 0, "by_scenario": {}}
    per_incident = attacks.groupby("incident_id").agg(scenario=("scenario", "first"), caught=("flagged", "any"))
    by_scenario = {
        s: {"caught": int(g.caught.sum()), "total": len(g), "recall": round(float(g.caught.mean()), 3)}
        for s, g in per_incident.groupby("scenario")
    }
    return {
        "overall": round(float(per_incident.caught.mean()), 3),
        "n_incidents": len(per_incident),
        "by_scenario": by_scenario,
    }
