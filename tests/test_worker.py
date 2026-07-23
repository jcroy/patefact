import io
import json
import httpx
from opendir.infra.worker import capture_all
from opendir.capture.fetcher import Fetcher

LISTING = ("<html><head><title>Index of /</title></head><body>"
           "<a href='a.zip'>a.zip</a></body></html>")


def _fetcher():
    def handler(request):
        if request.url.path == "/favicon.ico":
            return httpx.Response(404)
        return httpx.Response(200, headers=[("Server", "nginx")], text=LISTING)
    return Fetcher(transport=httpx.MockTransport(handler), min_interval=0)


def test_capture_all_emits_one_jsonl_record_per_url_without_body():
    out = io.StringIO()
    capture_all(["http://ex.com/a/", "http://ex.com/b/"], _fetcher(), out)
    lines = [l for l in out.getvalue().splitlines() if l]
    assert len(lines) == 2
    recs = [json.loads(l) for l in lines]
    assert recs[0]["url"] == "http://ex.com/a/"
    assert recs[0]["is_open_dir"] is True
    assert "body" not in recs[0]           # raw HTML must never leave the droplet


def test_capture_all_records_error_without_aborting_batch():
    class Boom:
        egress = "local"
        def fetch(self, url):
            raise RuntimeError("boom")
        def throttle(self, url):
            pass
    out = io.StringIO()
    capture_all(["http://x/", "http://y/"], Boom(), out)
    recs = [json.loads(l) for l in out.getvalue().splitlines() if l]
    assert len(recs) == 2                   # batch continued past the failure
    assert "boom" in recs[0]["error"]
    assert recs[1]["url"] == "http://y/"


def test_capture_all_skips_blank_lines():
    out = io.StringIO()
    capture_all(["http://ex.com/a/", "", "  "], _fetcher(), out)
    assert len([l for l in out.getvalue().splitlines() if l]) == 1


def test_capture_all_concurrent_emits_every_record_intact():
    """With concurrency>1 every URL still yields exactly one well-formed JSONL
    line (order may differ; write lock keeps lines from interleaving)."""
    urls = [f"http://ex.com/{i}/" for i in range(25)]
    out = io.StringIO()
    capture_all(urls, _fetcher(), out, concurrency=8)
    lines = [l for l in out.getvalue().splitlines() if l]
    recs = [json.loads(l) for l in lines]          # every line parses (no interleaving)
    assert len(recs) == 25
    assert {r["url"] for r in recs} == set(urls)    # all present, none dropped/dup
    assert all(r["is_open_dir"] is True and "body" not in r for r in recs)


def test_capture_all_concurrent_records_errors_without_dropping():
    class Boom:
        egress = "local"
        def fetch(self, url):
            raise RuntimeError("boom")
        def throttle(self, url):
            pass
    out = io.StringIO()
    capture_all([f"http://x/{i}/" for i in range(10)], Boom(), out, concurrency=5)
    recs = [json.loads(l) for l in out.getvalue().splitlines() if l]
    assert len(recs) == 10 and all("boom" in r["error"] for r in recs)
