"""DB-facing classification service.

Bridges the pure ``opendir.classify.features``/``opendir.classify.rules``
functions to the ``Classification`` model: extracts features from a
Snapshot's listing_entries, runs the rules-first classifier, and persists
the result as a new (append-only) Classification row.
"""

from opendir.classify.features import extract_features
from opendir.classify.rules import classify
from opendir.models import Classification, Snapshot


def classify_snapshot(snapshot: Snapshot) -> Classification:
    """Classify a single open-directory Snapshot and persist the result.

    Callers are expected to filter to ``is_open_dir=True`` snapshots; this
    function does not check that itself, it only extracts/classifies/persists.
    """
    features = extract_features(
        snapshot.listing_entries,
        server_kind=snapshot.server_kind,
        tls=snapshot.tls,
    )
    result = classify(features)
    return Classification.objects.create(
        snapshot=snapshot,
        label=result["label"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        features=features,
        extractor_version=result["extractor_version"],
        ruleset_version=result["ruleset_version"],
    )
