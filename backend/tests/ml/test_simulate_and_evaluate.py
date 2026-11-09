import numpy as np
import pandas as pd
import pytest

from app.ml.evaluate import best_threshold, confusion_metrics, incident_recall
from app.ml.simulate import SCENARIOS, simulate_dataset

# ---- simulator: determinism and leakage guarantees ----------------------------------


def test_simulation_is_deterministic():
    a, b = simulate_dataset(seed=3, quick=True), simulate_dataset(seed=3, quick=True)
    pd.testing.assert_frame_equal(a["test"], b["test"])
    assert not a["test"].equals(simulate_dataset(seed=4, quick=True)["test"])


def test_splits_do_not_overlap_in_time(quick_data):
    assert quick_data["train"].timestamp.max() < quick_data["val"].timestamp.min()
    assert quick_data["val"].timestamp.max() < quick_data["test"].timestamp.min()


def test_attacker_ips_never_cross_splits(quick_data):
    """The leakage test: no attacker IP in train may appear in validation or test."""
    ips = {name: set(df[df.is_attack].source_ip) for name, df in quick_data.items()}
    assert ips["train"] and ips["val"] and ips["test"]
    assert not ips["train"] & ips["val"]
    assert not ips["train"] & ips["test"]
    assert not ips["val"] & ips["test"]


def test_attack_ips_never_appear_in_normal_traffic(quick_data):
    for df in quick_data.values():
        attacker = set(df[df.is_attack].source_ip)
        assert not attacker & set(df[~df.is_attack].source_ip)


def test_classes_are_imbalanced_and_all_scenarios_present(labeled, quick_data):
    for df in labeled.values():
        assert 0.005 < df["y"].mean() < 0.25  # attacks are rare
    seen = set(pd.concat(quick_data.values()).query("is_attack").scenario)
    assert seen <= set(SCENARIOS) and len(seen) >= 4


# ---- metrics -----------------------------------------------------------------------


def test_confusion_metrics_known_values():
    y_true = np.array([1, 1, 1, 0, 0, 0, 0, 0])
    y_pred = np.array([1, 1, 0, 1, 0, 0, 0, 0])
    m = confusion_metrics(y_true, y_pred)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 4)
    assert m["precision"] == pytest.approx(0.667, abs=1e-3)
    assert m["recall"] == pytest.approx(0.667, abs=1e-3)
    assert m["fpr"] == pytest.approx(0.2)


def test_never_alerting_has_zero_recall_despite_high_accuracy():
    y_true = np.array([1] + [0] * 99)
    m = confusion_metrics(y_true, np.zeros(100))
    assert m["recall"] == 0.0 and m["precision"] == 0.0
    assert (m["tn"] + m["tp"]) / 100 == 0.99  # "99% accurate", and useless


def test_best_threshold_separates_clean_scores():
    y = np.array([0, 0, 0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.9, 0.95])
    thr = best_threshold(y, scores, candidates=np.array([0.05, 0.5, 0.92, 0.99]))
    assert confusion_metrics(y, scores >= thr)["f1"] in (0.667, 1.0)
    assert thr in (0.5,)  # catches both attacks with no false alarms; ties prefer the higher value only if equal F1


def test_incident_recall_counts_an_attack_once_if_any_bucket_flagged():
    labeled = pd.DataFrame(
        {
            "incident_id": [0, 0, 0, 1, -1, -1],
            "scenario": ["low_and_slow"] * 3 + ["brute_force", "", ""],
        }
    )
    flagged = np.array([False, True, False, False, False, True])
    out = incident_recall(labeled, flagged)
    assert out["overall"] == 0.5 and out["n_incidents"] == 2
    assert out["by_scenario"]["low_and_slow"]["caught"] == 1
    assert out["by_scenario"]["brute_force"]["caught"] == 0
