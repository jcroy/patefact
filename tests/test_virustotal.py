import pytest
from django.core.management import call_command

from opendir.enrich import virustotal
from opendir.enrich.virustotal import lookup_hash
from opendir.models import Candidate, PayloadHash, Snapshot


class FakeResponse:
    """Minimal httpx.Response-like stand-in for injected clients."""

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


CANNED_200 = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 42,
                "suspicious": 1,
                "harmless": 10,
                "undetected": 17,
            },
            "type_description": "Win32 EXE",
            "meaningful_name": "evil.exe",
        }
    }
}


def test_lookup_hash_found_parses_stats_and_hits_files_endpoint():
    calls = []

    def fake_client(url, headers):
        calls.append(url)
        return FakeResponse(200, CANNED_200)

    result = lookup_hash("abc", client=fake_client)

    assert result == {
        "found": True,
        "malicious": 42,
        "suspicious": 1,
        "total": 70,
        "type": "Win32 EXE",
        "name": "evil.exe",
    }
    # Lookup-only proof: the client was only ever called with the
    # files-by-hash GET endpoint -- never a submit/scan/analyse path.
    assert len(calls) == 1
    assert "/api/v3/files/" in calls[0]
    assert calls[0].endswith("/abc")


def test_lookup_hash_not_found_returns_found_false():
    def fake_client(url, headers):
        return FakeResponse(404)

    assert lookup_hash("deadbeef", client=fake_client) == {"found": False}


def test_lookup_hash_error_status_returns_found_false_with_error():
    def fake_client(url, headers):
        return FakeResponse(500)

    assert lookup_hash("deadbeef", client=fake_client) == {
        "found": False,
        "error": "vt 500",
    }


def test_lookup_hash_never_touches_a_submit_endpoint():
    seen_urls = []

    def fake_client(url, headers):
        seen_urls.append(url)
        # VT's submit/rescan/analyse paths must never be hit by a lookup.
        assert "/analyse" not in url
        assert "/analyze" not in url
        return FakeResponse(200, CANNED_200)

    lookup_hash("abc", client=fake_client)
    assert all("/files/" in u for u in seen_urls)


def _make_snapshot(url="http://x.example/"):
    c = Candidate.objects.create(dedup_key=url, url=url, source="fake")
    return Snapshot.objects.create(
        candidate=c,
        http_status=200,
        server_kind="apache",
        is_open_dir=True,
        listing_entries=[],
        entry_count=0,
    )


@pytest.mark.django_db
def test_vt_lookup_command_populates_vt_and_skips_done_and_empty_hash(monkeypatch):
    snap = _make_snapshot()
    todo = PayloadHash.objects.create(
        snapshot=snap, name="a.exe", url="http://x/a.exe", sha256="aaa"
    )
    already_done = PayloadHash.objects.create(
        snapshot=snap,
        name="b.exe",
        url="http://x/b.exe",
        sha256="bbb",
        vt={"found": True, "malicious": 0},
    )
    no_hash = PayloadHash.objects.create(
        snapshot=snap, name="c.exe", url="http://x/c.exe", sha256=""
    )

    calls = []

    def fake_lookup(sha256, **kwargs):
        calls.append(sha256)
        return {
            "found": True,
            "malicious": 5,
            "suspicious": 0,
            "total": 10,
            "type": "x",
            "name": "y",
        }

    monkeypatch.setattr(virustotal, "lookup_hash", fake_lookup)
    monkeypatch.setattr("time.sleep", lambda s: None)

    call_command("vt_lookup")

    todo.refresh_from_db()
    already_done.refresh_from_db()
    no_hash.refresh_from_db()

    assert todo.vt == {
        "found": True,
        "malicious": 5,
        "suspicious": 0,
        "total": 10,
        "type": "x",
        "name": "y",
    }
    # Already-enriched and empty-sha256 rows are left untouched.
    assert already_done.vt == {"found": True, "malicious": 0}
    assert no_hash.vt is None

    # Only the one pending, non-empty-hash row was looked up.
    assert calls == ["aaa"]


@pytest.mark.django_db
def test_vt_lookup_command_sleeps_between_but_not_after_last_call(monkeypatch):
    snap = _make_snapshot()
    PayloadHash.objects.create(snapshot=snap, name="a.exe", url="http://x/a.exe", sha256="aaa")
    PayloadHash.objects.create(snapshot=snap, name="b.exe", url="http://x/b.exe", sha256="bbb")

    monkeypatch.setattr(
        virustotal, "lookup_hash", lambda sha256, **kwargs: {"found": False}
    )
    sleep_calls = []
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    call_command("vt_lookup", sleep=7)

    # Two rows looked up -> exactly one sleep in between, not a trailing one.
    assert sleep_calls == [7]


def test_lookup_hash_handles_network_error_without_raising():
    import httpx
    from opendir.enrich.virustotal import lookup_hash
    def raising_client(url, headers):
        raise httpx.ConnectError("boom")
    r = lookup_hash("abc123", client=raising_client)
    assert r["found"] is False and "boom" in r["error"]
