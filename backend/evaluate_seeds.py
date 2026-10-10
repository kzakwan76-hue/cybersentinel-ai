"""Repeat the whole experiment over many random seeds and report the mean and spread.

Run from the project root:  python backend\\evaluate_seeds.py [number_of_runs]
"""

import statistics
import sys

from app.ml.experiment import METHODS, run_experiment

SHORT = {
    "Rules (count only)": "rules",
    "Rules (with timing)": "rules+time",
    "Forest only": "forest",
    "ML (full)": "ML",
    "Rules(count) + ML": "r+ML",
    "Rules(timing) + ML": "r+t+ML",
}


def spread(values: list[float]) -> str:
    deviation = statistics.stdev(values)
    return f"{statistics.mean(values):.2f} +/- {deviation:.2f} [{min(values):.2f}-{max(values):.2f}]"


def main() -> None:
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    if runs < 2:
        raise SystemExit("Use at least 2 runs.")

    results = []
    for number, seed in enumerate(range(1, runs + 1), start=1):
        results.append(run_experiment(seed))
        print(f"finished seed {seed} ({number}/{runs})", flush=True)

    print(f"\n{runs} runs, each with a new synthetic dataset, a new 70/30 split and a new model seed.")
    print("Values are mean +/- standard deviation [min-max] over the runs.\n")

    header = f"{'Method':<22}{'Precision':<30}{'Recall':<30}{'F1':<30}"
    print(header)
    print("-" * len(header))
    for method in METHODS:
        cells = "".join(
            spread([getattr(run.metrics[method], attribute) for run in results]).ljust(30)
            for attribute in ("precision", "recall", "f1")
        )
        print(f"{method:<22}{cells}")

    print("\nShare of sessions flagged, per session type (mean over runs).")
    print("Attack types: higher is better. Normal types: lower is better.")
    header = f"{'session type':<20}{'attack?':<9}" + "".join(f"{SHORT[m]:>11}" for m in METHODS)
    print(header)
    print("-" * len(header))
    kinds = sorted(
        {kind for run in results for kind in run.flag_rate_by_kind},
        key=lambda kind: (next(run for run in results if kind in run.kind_is_attack).kind_is_attack[kind], kind),
    )
    for kind in kinds:
        present = [run for run in results if kind in run.flag_rate_by_kind]
        attack = "yes" if present[0].kind_is_attack[kind] else "no"
        cells = "".join(
            f"{statistics.mean(run.flag_rate_by_kind[kind][m] for run in present):>11.2f}" for m in METHODS
        )
        print(f"{kind:<20}{attack:<9}{cells}")


if __name__ == "__main__":
    main()