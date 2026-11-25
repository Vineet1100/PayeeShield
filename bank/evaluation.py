"""Compare the fraud detectors on a labelled synthetic test set.

Run:  python -m bank.evaluation

Normal purchases come from the same distribution as the training history (new seed),
and fraud is injected in four patterns. Each detector is scored on precision, recall
and false-positive rate, plus recall per pattern so you can see what each one misses.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import fraud

NORMAL_COUNT = 1000
PER_PATTERN = 50
PATTERNS = ("large amount", "night-time", "card testing", "large at night")


def labelled_purchases(seed: int = 7) -> dict[str, np.ndarray]:
    """Normal purchases (label "normal") plus PER_PATTERN of each fraud pattern."""
    normal = fraud.simulate_purchases(NORMAL_COUNT, seed)
    # fraud starts from normal purchases (own seed), then one or two features are pushed out
    base = fraud.simulate_purchases(len(PATTERNS) * PER_PATTERN, seed + 1)
    rng = np.random.default_rng(seed + 2)
    amount, hour, online = base["amount"], base["hour"], base["online"]
    pattern = np.repeat(PATTERNS, PER_PATTERN)

    big = (pattern == "large amount") | (pattern == "large at night")
    night = (pattern == "night-time") | (pattern == "large at night")
    testing = pattern == "card testing"
    amount[big] *= rng.uniform(8, 25, big.sum())
    hour[night] = rng.integers(0, 6, night.sum())
    # card testers try tiny online charges to see if stolen details work
    online[testing] = True
    amount[testing] = rng.uniform(0.5, 3, testing.sum())

    return {
        "amount": np.concatenate([normal["amount"], amount]),
        "hour": np.concatenate([normal["hour"], hour]),
        "online": np.concatenate([normal["online"], online]),
        "label": np.concatenate([np.full(NORMAL_COUNT, "normal"), pattern]),
    }


def _isolation_forest():
    # same features and contamination as the LOF model, so only the method differs
    h = fraud._history()
    model = make_pipeline(StandardScaler(), IsolationForest(contamination=0.01, random_state=0))
    return model.fit(fraud._features(h["amount"], h["hour"], h["online"]))


def predictions(data: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    """Which purchases each detector flags."""
    scores = [
        fraud.score(float(a), int(h), bool(o))
        for a, h, o in zip(data["amount"], data["hour"], data["online"], strict=True)
    ]
    features = fraud._features(data["amount"], data["hour"], data["online"])
    return {
        "Robust z-score": np.array([s.robust_z > fraud.ROBUST_Z_LIMIT for s in scores]),
        "Local Outlier Factor": np.array([s.lof_flagged for s in scores]),
        "Isolation Forest": _isolation_forest().predict(features) == -1,
        "Bank (z-score or LOF)": np.array([s.flagged for s in scores]),
    }


def metrics(flagged: np.ndarray, is_fraud: np.ndarray) -> dict[str, float]:
    tp = int((flagged & is_fraud).sum())
    fp = int((flagged & ~is_fraud).sum())
    fn = int((~flagged & is_fraud).sum())
    tn = int((~flagged & ~is_fraud).sum())
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def report() -> str:
    """The comparison as a Markdown table."""
    data = labelled_purchases()
    is_fraud = data["label"] != "normal"
    header = ["Detector", "Precision", "Recall", "False-positive rate"] + [
        f"Recall: {p}" for p in PATTERNS
    ]
    rows = [header, ["---"] * len(header)]
    for name, flagged in predictions(data).items():
        m = metrics(flagged, is_fraud)
        per_pattern = [f"{flagged[data['label'] == p].mean():.0%}" for p in PATTERNS]
        rows.append(
            [
                name,
                f"{m['precision']:.0%}",
                f"{m['recall']:.0%}",
                f"{m['false_positive_rate']:.1%}",
                *per_pattern,
            ]
        )
    return "\n".join("| " + " | ".join(r) + " |" for r in rows)


if __name__ == "__main__":
    print(report())
