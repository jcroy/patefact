#!/usr/bin/env python
"""Evaluate the classifier against the behavioral gold set.

Prints a per-case table, a confusion matrix, and overall accuracy. Pure --
no DB, no network. Use it to sanity-check a ruleset change before bumping
the version, and as the source of the "classifier validated against N gold
cases" figure quoted in the README/dashboard.

    uv run python scripts/eval_classifier.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from opendir.classify.features import extract_features, EXTRACTOR_VERSION  # noqa: E402
from opendir.classify.rules import classify, RULESET_VERSION  # noqa: E402
from opendir.classify.goldset import GOLD_CASES  # noqa: E402

LABELS = ["malicious_staging", "sensitive_exposure", "intentional_public", "benign_index"]


def main():
    results = []
    for cid, entries, sk, expected, note in GOLD_CASES:
        got = classify(extract_features(entries, server_kind=sk))["label"]
        results.append((cid, expected, got, got == expected, note))

    correct = sum(1 for *_x, ok, _n in results if ok)
    total = len(results)

    print(f"Classifier gold-set evaluation")
    print(f"  extractor v{EXTRACTOR_VERSION} | ruleset v{RULESET_VERSION}")
    print(f"  accuracy: {correct}/{total} = {100 * correct / total:.1f}%\n")

    width = max(len(c[0]) for c in results)
    print(f"  {'case'.ljust(width)}  {'expected':<18} {'got':<18} ok")
    print(f"  {'-' * width}  {'-' * 18} {'-' * 18} --")
    for cid, expected, got, ok, _note in results:
        mark = "✓" if ok else "✗ MISMATCH"
        print(f"  {cid.ljust(width)}  {expected:<18} {got:<18} {mark}")

    # confusion matrix (rows = expected, cols = predicted)
    print("\n  confusion matrix (row=expected, col=predicted):")
    idx = {lab: i for i, lab in enumerate(LABELS)}
    mat = [[0] * len(LABELS) for _ in LABELS]
    for _cid, expected, got, _ok, _n in results:
        if expected in idx and got in idx:
            mat[idx[expected]][idx[got]] += 1
    abbr = [lab[:4] for lab in LABELS]
    print("    " + " " * 20 + " ".join(f"{a:>5}" for a in abbr))
    for lab in LABELS:
        row = " ".join(f"{mat[idx[lab]][idx[c]]:>5}" for c in LABELS)
        print(f"    {lab:<20}{row}")

    sys.exit(0 if correct == total else 1)


if __name__ == "__main__":
    main()
