"""Synthetic privacy evaluation utilities."""

from app.evaluation.metrics import EvaluationReport, evaluate_dataset, score_spans
from app.evaluation.synthetic_dataset import (
    SyntheticDocument,
    SyntheticEntity,
    load_synthetic_dataset,
)

__all__ = [
    "EvaluationReport",
    "SyntheticDocument",
    "SyntheticEntity",
    "evaluate_dataset",
    "load_synthetic_dataset",
    "score_spans",
]
