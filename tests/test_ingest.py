import json
import pytest
from opendir.models import Candidate, Snapshot
from opendir.infra.ingest import ingest_jsonl


def _ok(url):
    return {"url": url, "error": "", "http_status": 200, "final_url": url,
            "headers": [("server", "nginx")], "server_banner": "nginx",
            "server_kind": "nginx", "title": "Index of /", "is_open_dir": True,
            "listing_entries": [], "entry_count": 0, "raw_html_sha256": "aa",
            "header_order_sha256": "bb", "template_sha256": "cc",
            "favicon_sha256": None, "tls": None}


@pytest.mark.django_db
def test_ingest_jsonl_creates_snapshots_and_counts(tmp_path):
    c1 = Candidate.objects.create(dedup_key="a", url="http://a/", source="fake")
    c2 = Candidate.objects.create(dedup_key="b", url="http://b/", source="fake")
    p = tmp_path / "results.jsonl"
    p.write_text(
        json.dumps(_ok("http://a/")) + "\n"
        + json.dumps({"url": "http://b/", "error": "timeout", "http_status": None, "final_url": "http://b/"}) + "\n"
        + json.dumps(_ok("http://unknown/")) + "\n"
    )
    stats = ingest_jsonl(str(p))
    assert stats.snapshots == 1
    assert stats.errors == 1
    assert stats.unmatched == 1
    c1.refresh_from_db(); c2.refresh_from_db()
    assert c1.status == "captured" and c2.status == "error"
    assert Snapshot.objects.count() == 2          # unknown url created nothing
    assert not Candidate.objects.filter(url="http://unknown/").exists()


@pytest.mark.django_db
def test_ingest_jsonl_skips_blank_lines(tmp_path):
    Candidate.objects.create(dedup_key="a", url="http://a/", source="fake")
    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps(_ok("http://a/")) + "\n\n  \n")
    stats = ingest_jsonl(str(p))
    assert stats.snapshots == 1


@pytest.mark.django_db
def test_ingest_jsonl_survives_malformed_line(tmp_path):
    Candidate.objects.create(dedup_key="a", url="http://a/", source="fake")
    p = tmp_path / "r.jsonl"
    p.write_text("{ this is not json\n" + json.dumps(_ok("http://a/")) + "\n")
    stats = ingest_jsonl(str(p))
    assert stats.malformed == 1
    assert stats.snapshots == 1        # batch continued past the bad line


@pytest.mark.django_db
def test_ingest_jsonl_counts_schema_drift_as_malformed(tmp_path):
    Candidate.objects.create(dedup_key="a", url="http://a/", source="fake")
    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps({"url": "http://a/", "http_status": 200}) + "\n")  # missing required fields
    stats = ingest_jsonl(str(p))
    assert stats.malformed == 1 and stats.snapshots == 0
