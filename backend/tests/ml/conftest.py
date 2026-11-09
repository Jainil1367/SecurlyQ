import pytest

from app.ml.detector import AnomalyDetector
from app.ml.features import build_features
from app.ml.simulate import simulate_dataset
from app.ml.train import label_features


@pytest.fixture(scope="session")
def quick_data():
    return simulate_dataset(seed=7, quick=True)


@pytest.fixture(scope="session")
def labeled(quick_data):
    return {name: label_features(df) for name, df in quick_data.items()}


@pytest.fixture(scope="session")
def trained_detector(quick_data):
    """One small model shared by all tests (training is the slow part)."""
    return AnomalyDetector().fit(build_features(quick_data["train"]))
