"""Model evaluation: precision, recall, F1 and the confusion matrix."""

from dataclasses import dataclass

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support


@dataclass(frozen=True)
class Metrics:
    precision: float
    recall: float
    f1: float
    true_negatives: int
    false_positives: int
    false_negatives: int
    true_positives: int


def evaluate(y_true: list[int], y_pred: list[int]) -> Metrics:
    """y values: 1 = attack, 0 = normal."""
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=1, zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return Metrics(float(precision), float(recall), float(f1), int(tn), int(fp), int(fn), int(tp))