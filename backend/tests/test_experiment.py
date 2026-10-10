import pytest

from app.ml.experiment import METHODS, run_experiment

SMALL = {"n_normal": 200, "n_attack": 60}  # small so the tests (and CI) stay fast


@pytest.fixture(scope="module")
def result():
    return run_experiment(3, **SMALL)


def test_every_method_is_scored_with_valid_numbers(result):
    assert list(result.metrics) == METHODS
    for metrics in result.metrics.values():
        for value in (metrics.precision, metrics.recall, metrics.f1):
            assert 0.0 <= value <= 1.0


def test_same_seed_gives_identical_results(result):
    assert run_experiment(3, **SMALL) == result


def test_different_seeds_give_different_data():
    assert run_experiment(4, **SMALL) != run_experiment(5, **SMALL)


def test_combining_with_ml_never_lowers_recall(result):
    # "Combined" flags a superset of what either part flags, so recall can only go up.
    m = result.metrics
    assert m["Rules(count) + ML"].recall >= m["Rules (count only)"].recall
    assert m["Rules(timing) + ML"].recall >= m["Rules (with timing)"].recall
    assert m["Rules(timing) + ML"].recall >= m["ML (full)"].recall


def test_range_guard_only_adds_flags(result):
    forest, full = result.metrics["Forest only"], result.metrics["ML (full)"]
    assert full.recall >= forest.recall
    assert full.false_positives >= forest.false_positives