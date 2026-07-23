from io import StringIO

import pytest
from django.core.management import call_command

import opendir.payload.service as service
from opendir.classify.rules import RULESET_VERSION
from opendir.models import Candidate, Classification, PayloadHash, Snapshot


def _make_snapshot(url, entries, label, is_open_dir=True):
    c = Candidate.objects.create(dedup_key=url, url=url, source="fake")
    snap = Snapshot.objects.create(
        candidate=c,
        http_status=200,
        server_kind="apache",
        is_open_dir=is_open_dir,
        listing_entries=entries,
        entry_count=len(entries),
    )
    Classification.objects.create(
        snapshot=snap,
        label=label,
        confidence=0.9,
        reasons=[],
        features={},
        extractor_version="1",
        ruleset_version=RULESET_VERSION,
    )
    return snap


ENTRIES = [
    {"name": "mal.exe", "is_dir": False},
    {"name": "data.sql", "is_dir": False},
    {"name": "x.jpg", "is_dir": False},
]


@pytest.mark.django_db
def test_hash_payloads_only_hashes_allowlisted_file_and_persists(monkeypatch):
    snap = _make_snapshot("http://mal.example/", ENTRIES, "malicious_staging")
    mal_url = "http://mal.example/mal.exe"

    calls = []

    def fake_remote_hash(urls, user_agent, timeout, max_bytes):
        calls.append(urls)
        return [{"url": mal_url, "sha256": "abc123", "md5": "d4", "tlsh": None,
                  "size": 1234, "error": ""}]

    monkeypatch.setattr(service, "_default_remote_hash", fake_remote_hash)

    out = StringIO()
    call_command("hash_payloads", stdout=out)

    # Exactly one PayloadHash created (only mal.exe was in the allowlist).
    assert PayloadHash.objects.count() == 1
    row = PayloadHash.objects.get()
    assert row.snapshot_id == snap.id
    assert row.sha256 == "abc123"
    assert row.name == "mal.exe"

    # The fake was called with ONLY the mal.exe url -- data.sql/x.jpg were
    # never sent to Modal (the CSAM/PII safety property).
    assert len(calls) == 1
    assert calls[0] == [mal_url]

    # Re-running does not duplicate (the .exclude(payload_hashes__isnull=False) gate).
    call_command("hash_payloads", stdout=StringIO())
    assert PayloadHash.objects.count() == 1
    assert len(calls) == 1


@pytest.mark.django_db
def test_hash_payloads_skips_benign_snapshot(monkeypatch):
    _make_snapshot("http://benign.example/", ENTRIES, "benign_index")

    def fake_remote_hash(urls, user_agent, timeout, max_bytes):
        raise AssertionError("remote hashing must not be called for benign snapshots")

    monkeypatch.setattr(service, "_default_remote_hash", fake_remote_hash)

    call_command("hash_payloads", stdout=StringIO())

    assert PayloadHash.objects.count() == 0
