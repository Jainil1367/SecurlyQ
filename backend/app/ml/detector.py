"""AnomalyDetector: an Isolation Forest wrapped in a small, testable class.

How an Isolation Forest works (the intuition):
    Build many random decision trees that split the data on random features at
    random values. Rare, unusual points get isolated from the crowd in very few
    splits (short path); normal points sit deep in the crowd (long path).
    "Average path length is short" => anomaly. It never needs labels, which is why
    it suits security data where labeled attacks are scarce.

Design choices worth studying:
* Tree models only care about the *order* of values, so no feature scaling needed.
* Raw scores are hard to interpret ("-0.43 means?"), so we convert each one to its
  **percentile among training scores** (0..1). A score of 0.99 reads as "more
  unusual than 99% of the buckets we trained on" and the threshold becomes an
  *alert budget*: 0.99 means roughly 1% of normal buckets will fire.
* We store the training mean/std of each feature so we can explain *why* a bucket
  scored high ("14 failures, 11 standard deviations above normal").
"""

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

from app.ml.features import FEATURE_LABELS, FEATURES

logger = logging.getLogger("securlyq.ml")

MODEL_VERSION = "isolation-forest-v1"


class ModelIntegrityError(Exception):
    """The model file does not match its recorded checksum."""


class AnomalyDetector:
    def __init__(self, n_estimators: int = 200, random_state: int = 42, threshold: float = 0.99):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.threshold = threshold
        self.model: IsolationForest | None = None
        self.train_scores: np.ndarray | None = None
        self.feature_means: dict[str, float] = {}
        self.feature_stds: dict[str, float] = {}
        self.metadata: dict = {}

    # ------------------------------------------------------------------ training
    def fit(self, features: pd.DataFrame) -> "AnomalyDetector":
        X = features[FEATURES].to_numpy(dtype=float)
        self.model = IsolationForest(
            n_estimators=self.n_estimators, contamination="auto", random_state=self.random_state
        ).fit(X)
        self.train_scores = np.sort(self._raw(X))
        self.feature_means = {f: float(features[f].mean()) for f in FEATURES}
        # Floor the std so a constant feature can't produce infinite z-scores.
        self.feature_stds = {f: max(float(features[f].std(ddof=0)), 1e-6) for f in FEATURES}
        self.metadata = {
            "model_version": MODEL_VERSION,
            "trained_at": datetime.now(UTC).isoformat(),
            "n_train_rows": len(features),
            "sklearn_version": sklearn.__version__,
            "features": FEATURES,
        }
        return self

    # ------------------------------------------------------------------- scoring
    def _raw(self, X: np.ndarray) -> np.ndarray:
        assert self.model is not None, "call fit() or load() first"
        return -self.model.score_samples(X)  # flip sign: higher = more anomalous

    def score(self, features: pd.DataFrame) -> np.ndarray:
        """Anomaly score in [0, 1]: the fraction of training buckets this one is at least as unusual as."""
        if features.empty:
            return np.array([])
        raw = self._raw(features[FEATURES].to_numpy(dtype=float))
        assert self.train_scores is not None
        return np.searchsorted(self.train_scores, raw, side="right") / len(self.train_scores)

    def explain(self, row: pd.Series, top: int = 3) -> list[dict]:
        """The features that deviate most from training-time normal, as z-scores."""
        parts = []
        for f in FEATURE_LABELS:  # hour_sin/hour_cos are model inputs, but meaningless to a human as z-scores
            z = (float(row[f]) - self.feature_means[f]) / self.feature_stds[f]
            parts.append(
                {"feature": f, "label": FEATURE_LABELS[f], "value": round(float(row[f]), 2), "z_score": round(z, 1)}
            )
        parts.sort(key=lambda p: abs(p["z_score"]), reverse=True)
        return parts[:top]

    # --------------------------------------------------------------- persistence
    def save(self, path: str | Path) -> str:
        """Write the model plus a SHA-256 sidecar file. Returns the checksum."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "train_scores": self.train_scores,
                "feature_means": self.feature_means,
                "feature_stds": self.feature_stds,
                "threshold": self.threshold,
                "metadata": self.metadata,
            },
            path,
        )
        digest = _sha256(path)
        Path(f"{path}.sha256").write_text(digest + "\n")
        return digest

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        """Load a model after verifying its checksum.

        Security lesson: joblib/pickle files can execute arbitrary code when loaded.
        NEVER load a model file you don't control. The checksum catches accidental
        corruption and casual tampering; in production the real defense is a private,
        versioned S3 bucket that only the training job can write to.
        """
        path = Path(path)
        sidecar = Path(f"{path}.sha256")
        if not sidecar.exists() or sidecar.read_text().strip() != _sha256(path):
            raise ModelIntegrityError(f"Checksum mismatch or missing for {path}")
        blob = joblib.load(path)
        det = cls(threshold=blob["threshold"])
        det.model = blob["model"]
        det.train_scores = blob["train_scores"]
        det.feature_means = blob["feature_means"]
        det.feature_stds = blob["feature_stds"]
        det.metadata = blob["metadata"]
        return det


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
