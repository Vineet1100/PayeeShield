"""A/B test two fraud-alert thresholds on the same traffic.

Run:  python -m bank.ab_test

Both variants score the same labelled purchases, so each purchase gives a paired result.
The difference in fraud caught, and in good customers flagged, is tested with an exact
McNemar test, which only counts the purchases where the two variants disagree.
"""

from math import comb

import numpy as np

from . import evaluation, fraud

# B lowers the LOF threshold from the model's own (about 1.83) to catch more fraud
VARIANT_B_LOF_THRESHOLD = 1.5
# a realistic share of fraud, for the false-alarm cost of each variant
FRAUD_RATE = 0.001


def traffic() -> dict[str, np.ndarray]:
    # a new seed, so the thresholds aren't judged on the detector comparison's test set,
    # and more good purchases, so false-positive rates are measurable
    return evaluation.labelled_purchases(seed=11, normal_count=5000)


def flags(data: dict[str, np.ndarray], lof_threshold: float) -> np.ndarray:
    """The bank's rule (z-score or LOF) with the LOF threshold set to lof_threshold."""
    z = np.array(
        [
            fraud._robust_z(float(a), bool(o))
            for a, o in zip(data["amount"], data["online"], strict=True)
        ]
    )
    features = fraud._features(data["amount"], data["hour"], data["online"])
    lof = -fraud._model().score_samples(features)
    return (z > fraud.ROBUST_Z_LIMIT) | (lof > lof_threshold)


def mcnemar_p(a_only: int, b_only: int) -> float:
    """Two-sided exact McNemar p-value from the counts where only A or only B flagged."""
    n = a_only + b_only
    if n == 0:
        return 1.0
    tail = sum(comb(n, i) for i in range(min(a_only, b_only) + 1)) / 2**n
    return min(1.0, 2 * tail)


def report() -> str:
    """The comparison as Markdown: one row per variant, then the significance tests."""
    data = traffic()
    is_fraud = data["label"] != "normal"
    current = -fraud._model()[-1].offset_
    variants = {
        f"A: current (LOF > {current:.2f})": flags(data, current),
        f"B: sensitive (LOF > {VARIANT_B_LOF_THRESHOLD:.2f})": flags(data, VARIANT_B_LOF_THRESHOLD),
    }
    cost_column = f"False alarms per fraud caught at 1 in {1 / FRAUD_RATE:,.0f}"
    rows = [
        f"| Variant | Fraud caught | Good customers flagged | {cost_column} |",
        "| --- | --- | --- | --- |",
    ]
    for name, flagged in variants.items():
        m = evaluation.metrics(flagged, is_fraud)
        cost = m["false_positive_rate"] * (1 - FRAUD_RATE) / (m["recall"] * FRAUD_RATE)
        rows.append(
            f"| {name} | {flagged[is_fraud].sum()} of {is_fraud.sum()} ({m['recall']:.1%}) "
            f"| {flagged[~is_fraud].sum()} of {(~is_fraud).sum():,}"
            f" ({m['false_positive_rate']:.2%}) | {cost:.1f} |"
        )

    a, b = variants.values()
    lines = ["", "McNemar exact test, A against B on the same purchases:", ""]
    for group, mask in (("Fraud caught", is_fraud), ("Good customers flagged", ~is_fraud)):
        a_only = int((a & ~b & mask).sum())
        b_only = int((b & ~a & mask).sum())
        lines.append(
            f"- {group}: {a_only} flagged only by A, {b_only} only by B,"
            f" p = {mcnemar_p(a_only, b_only):.2g}"
        )
    return "\n".join(rows + lines)


if __name__ == "__main__":
    print(report())
