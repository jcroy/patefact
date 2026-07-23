"""Regression suite: every gold case must classify to its intended label.

These run the full pipeline (extract_features -> classify) on the behavioral
gold set in ``opendir.classify.goldset``. Pure functions, no DB needed.
"""
import pytest

from opendir.classify.features import extract_features
from opendir.classify.rules import classify
from opendir.classify.goldset import GOLD_CASES


@pytest.mark.parametrize(
    "case_id,entries,server_kind,expected,note",
    GOLD_CASES,
    ids=[c[0] for c in GOLD_CASES],
)
def test_gold_case_classifies_as_expected(case_id, entries, server_kind, expected, note):
    features = extract_features(entries, server_kind=server_kind)
    result = classify(features)
    assert result["label"] == expected, (
        f"{case_id}: expected {expected}, got {result['label']} ({result['reasons']}). {note}"
    )


def test_gold_set_full_accuracy():
    """The gold set is ground-truth-by-construction; the classifier must score 100%.

    A drop here means a ruleset/extractor change altered intended behavior --
    bump the version and update the gold set deliberately, don't relax this.
    """
    correct = sum(
        classify(extract_features(entries, server_kind=sk))["label"] == expected
        for _cid, entries, sk, expected, _note in GOLD_CASES
    )
    assert correct == len(GOLD_CASES), f"{correct}/{len(GOLD_CASES)} gold cases correct"
