"""Load the trained model once per process, and degrade gracefully if it is unavailable."""

import logging
from functools import lru_cache

from app.core.config import get_settings
from app.ml.detector import AnomalyDetector

logger = logging.getLogger("securlyq.ml")


@lru_cache(maxsize=4)
def _load(path: str) -> AnomalyDetector | None:
    try:
        detector = AnomalyDetector.load(path)
    except Exception as exc:  # noqa: BLE001 - any failure means "run rules-only", never "crash analysis"
        logger.warning("anomaly model unavailable (%s: %s); running rules-only", type(exc).__name__, exc)
        return None
    logger.info("anomaly model loaded: %s", detector.metadata.get("model_version"))
    return detector


def get_detector() -> AnomalyDetector | None:
    return _load(get_settings().anomaly_model_path)


def clear_cache() -> None:
    _load.cache_clear()
