import numpy as np
import pytest

from app.ml.detector import AnomalyDetector, ModelIntegrityError
from app.ml.features import FEATURES
from app.ml.train import run


def test_scores_are_in_unit_interval(trained_detector, labeled):
    scores = trained_detector.score(labeled["test"])
    assert scores.min() >= 0.0 and scores.max() <= 1.0 and len(scores) == len(labeled["test"])


def test_attacks_score_higher_than_normal_traffic(trained_detector, labeled):
    test = labeled["test"]
    scores = trained_detector.score(test)
    assert scores[test["y"] == 1].mean() > scores[test["y"] == 0].mean() + 0.2


def test_scores_are_rank_normalized_on_training_data(trained_detector, labeled):
    """By construction ~1% of training rows score >= 0.99."""
    scores = trained_detector.score(labeled["train"])
    assert 0.002 < (scores >= 0.99).mean() < 0.03


def test_explain_names_the_driving_features_and_skips_time_encoding(trained_detector, labeled):
    test = labeled["test"]
    row = test.loc[test["n_failures"].idxmax()]
    top = trained_detector.explain(row)
    assert len(top) == 3
    assert {d["feature"] for d in top}.isdisjoint({"hour_sin", "hour_cos"})
    assert top[0]["z_score"] > 3  # the busiest-failing bucket is far from normal


def test_empty_frame_scores_to_empty_array(trained_detector, labeled):
    assert trained_detector.score(labeled["test"].iloc[0:0]).size == 0


def test_save_load_round_trip_gives_identical_scores(trained_detector, labeled, tmp_path):
    path = tmp_path / "m.joblib"
    trained_detector.save(path)
    loaded = AnomalyDetector.load(path)
    np.testing.assert_allclose(loaded.score(labeled["test"]), trained_detector.score(labeled["test"]))
    assert loaded.threshold == trained_detector.threshold
    assert loaded.metadata["features"] == FEATURES


def test_tampered_model_file_is_rejected(trained_detector, tmp_path):
    path = tmp_path / "m.joblib"
    trained_detector.save(path)
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(ModelIntegrityError):
        AnomalyDetector.load(path)


def test_missing_checksum_is_rejected(trained_detector, tmp_path):
    path = tmp_path / "m.joblib"
    trained_detector.save(path)
    (tmp_path / "m.joblib.sha256").unlink()
    with pytest.raises(ModelIntegrityError):
        AnomalyDetector.load(path)


def test_training_is_reproducible(labeled):
    a = AnomalyDetector().fit(labeled["train"])
    b = AnomalyDetector().fit(labeled["train"])
    np.testing.assert_allclose(a.score(labeled["test"]), b.score(labeled["test"]))


def test_train_pipeline_smoke(tmp_path):
    report = run(seed=7, quick=True, model_path=str(tmp_path / "model.joblib"), report_dir=tmp_path / "report")
    names = [r["approach"] for r in report["results"]]
    assert names[:3] == ["Rules only", "Isolation Forest only", "Hybrid (rules OR model)"]
    assert (tmp_path / "model.joblib").exists() and (tmp_path / "report" / "evaluation.md").exists()
    rules, model, hybrid = report["results"][:3]
    assert hybrid["recall"] >= max(rules["recall"], model["recall"])  # OR can only add detections
    assert report["model_ranking_quality"]["pr_auc"] > 3 * report["model_ranking_quality"]["pr_auc_baseline_always_positive"]
