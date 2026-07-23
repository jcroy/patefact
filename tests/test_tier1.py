import httpx
import pytest
from opendir.models import Candidate, Snapshot
from opendir.capture.fetcher import Fetcher, FetchResult
from opendir.capture.tier1 import capture_candidate, run_capture

LISTING = ("<html><head><title>Index of /files</title></head><body>"
           "<a href='/files/'>Parent Directory</a>"
           "<a href='sub/'>sub/</a><a href='data.zip'>data.zip</a></body></html>")

def _ok_fetcher():
    def handler(request):
        if request.url.path == "/favicon.ico":
            return httpx.Response(404)
        return httpx.Response(200, headers=[("Server", "Apache")], text=LISTING)
    return Fetcher(transport=httpx.MockTransport(handler))

@pytest.mark.django_db
def test_capture_truncates_overlong_title():
    # Arbitrary web HTML can carry a >512-char <title> (SEO spam); must not crash the insert.
    big_title = "Index of /" + "A" * 800
    html = f"<html><head><title>{big_title}</title></head><body>" \
           "<a href='data.zip'>data.zip</a></body></html>"
    def handler(request):
        if request.url.path == "/favicon.ico":
            return httpx.Response(404)
        return httpx.Response(200, headers=[("Server", "Apache")], text=html)
    c = Candidate.objects.create(dedup_key="ex.com/big", url="http://ex.com/big/", source="fake")
    snap = capture_candidate(c, fetcher=Fetcher(transport=httpx.MockTransport(handler)))
    c.refresh_from_db()
    assert c.status == "captured"
    assert len(snap.title) == 512

@pytest.mark.django_db
def test_capture_creates_snapshot_and_updates_candidate():
    c = Candidate.objects.create(dedup_key="ex.com/files", url="http://ex.com/files/", source="fake")
    snap = capture_candidate(c, fetcher=_ok_fetcher())
    c.refresh_from_db()
    assert c.status == "captured"
    assert c.last_captured_at is not None
    assert snap.http_status == 200
    assert snap.server_kind == "apache"
    assert snap.entry_count == 2                 # parent dir excluded
    assert snap.server_banner == "Apache"
    assert snap.is_open_dir is True
    assert snap.title and snap.title.startswith("Index of")
    assert snap.template_sha256 and snap.header_order_sha256
    assert snap.final_url == "http://ex.com/files/"

@pytest.mark.django_db
def test_capture_records_error_snapshot():
    c = Candidate.objects.create(dedup_key="ex.com/x", url="http://ex.com/x/", source="fake")
    def handler(request):
        raise httpx.ConnectError("refused")
    snap = capture_candidate(c, fetcher=Fetcher(transport=httpx.MockTransport(handler)))
    c.refresh_from_db()
    assert c.status == "error"
    assert "refused" in snap.error
    assert Snapshot.objects.count() == 1

@pytest.mark.django_db
def test_capture_uses_final_url_host_and_port_for_tls(monkeypatch):
    import opendir.capture.tier1 as tier1
    calls = {}
    def fake_fetch_tls(host, port=443):
        calls["host"] = host
        calls["port"] = port
        return {"sha256": "deadbeef", "self_signed": True}
    monkeypatch.setattr(tier1, "fetch_tls", fake_fetch_tls)

    def handler(request):
        if request.url.host == "start.example":
            return httpx.Response(302, headers={"location": "https://real.example:8443/"})
        return httpx.Response(200, headers=[("Server", "nginx")], text=LISTING)
    fetcher = Fetcher(transport=httpx.MockTransport(handler))

    c = Candidate.objects.create(dedup_key="start.example/", url="http://start.example/", source="fake")
    snap = capture_candidate(c, fetcher=fetcher)
    assert calls == {"host": "real.example", "port": 8443}
    assert snap.tls == {"sha256": "deadbeef", "self_signed": True}
    assert snap.final_url == "https://real.example:8443/"


class _EgressCapturedTlsFetcher:
    """Fake fetcher simulating the Modal egress path: the listing fetch already
    carries a TLS cert (captured from Modal's IP), so tier1 must reuse it
    instead of opening its own local connection."""
    def fetch(self, url):
        if url.endswith("/favicon.ico"):
            return FetchResult(url=url, final_url=url, status=404)
        return FetchResult(
            url=url, final_url="https://ex.com/", status=200,
            headers=[("server", "nginx")],
            body="<html><title>Index of /</title></html>",
            tls={"sha256": "deadbeef", "self_signed": True},
            error="",
        )


@pytest.mark.django_db
def test_capture_uses_egress_captured_tls_without_local_connection(monkeypatch):
    import opendir.capture.tier1 as tier1

    def fake_fetch_tls(host, port=443):
        raise AssertionError("local fetch_tls must not be called when result.tls is already populated")
    monkeypatch.setattr(tier1, "fetch_tls", fake_fetch_tls)

    c = Candidate.objects.create(dedup_key="ex.com/", url="https://ex.com/", source="fake")
    snap = capture_candidate(c, fetcher=_EgressCapturedTlsFetcher())
    assert snap.tls == {"sha256": "deadbeef", "self_signed": True}


class _RaisingModalFetcher:
    """Fake fetcher simulating egress='modal'. Its .fetch() must NEVER be
    called by capture_candidate -- under the new orchestration, the ENTIRE
    capture (fetch+parse+fingerprint) runs in the egress location, so
    capture_candidate only invokes _remote_capture / _default_remote_capture,
    never fetcher.fetch() directly."""
    egress = "modal"
    user_agent = "test-ua"
    timeout = 20.0
    max_bytes = 5_000_000
    max_redirects = 5

    def fetch(self, url):
        raise AssertionError("fetch() must not be called locally under egress=modal")

    def throttle(self, url):
        pass  # politeness throttling is exercised separately; not this fake's concern


@pytest.mark.django_db
def test_capture_modal_egress_no_cert_does_not_connect_locally(monkeypatch):
    # Simulates Modal's own TLS handshake failing (result.tls came back None).
    # Since the whole capture ran remotely, there is no local fetch_tls fallback
    # to guard against here anymore -- capture_candidate never sees raw HTML or
    # a host/port to connect to; it only receives this already-finished dict.
    import opendir.capture.tier1 as tier1

    def fake_fetch_tls(host, port=443):
        raise AssertionError("local fetch_tls must not be called under egress=modal")
    monkeypatch.setattr(tier1, "fetch_tls", fake_fetch_tls)

    canned = {
        "error": "", "http_status": 200, "final_url": "https://ex.com/",
        "headers": [("server", "nginx")], "server_banner": "nginx",
        "server_kind": "nginx", "title": "Index of /", "is_open_dir": True,
        "listing_entries": [], "entry_count": 0,
        "raw_html_sha256": "deadbeef", "header_order_sha256": "cafebabe",
        "template_sha256": "f00dface", "favicon_sha256": None,
        "tls": None,
    }
    monkeypatch.setattr(tier1, "_default_remote_capture",
                        lambda url, user_agent, timeout, max_bytes, max_redirects: canned)

    c = Candidate.objects.create(dedup_key="ex.com/", url="https://ex.com/", source="fake")
    snap = capture_candidate(c, fetcher=_RaisingModalFetcher())
    c.refresh_from_db()
    assert snap.tls is None
    assert c.status == "captured"


@pytest.mark.django_db
def test_capture_modal_egress_uses_remote_capture_not_local_parse(monkeypatch):
    """The core of this refactor: under egress='modal', capture_candidate must
    build the Snapshot straight from the structured dict Modal returns, and
    must NEVER call fetcher.fetch() locally (which would mean raw untrusted
    HTML crossed back to the operator's machine)."""
    import opendir.capture.tier1 as tier1

    canned = {
        "error": "", "http_status": 200, "final_url": "https://ex.com/files/",
        "headers": [("server", "Apache")], "server_banner": "Apache",
        "server_kind": "apache", "title": "Index of /files", "is_open_dir": True,
        "listing_entries": [{"name": "data.zip", "href": "data.zip", "is_dir": False,
                             "size": None, "mtime": None, "path": "/files/data.zip"}],
        "entry_count": 1,
        "raw_html_sha256": "abc123", "header_order_sha256": "def456",
        "template_sha256": "789xyz", "favicon_sha256": None,
        "tls": {"sha256": "deadbeef", "self_signed": True},
    }
    monkeypatch.setattr(tier1, "_default_remote_capture",
                        lambda url, user_agent, timeout, max_bytes, max_redirects: canned)

    c = Candidate.objects.create(dedup_key="ex.com/files", url="https://ex.com/files/", source="fake")
    snap = capture_candidate(c, fetcher=_RaisingModalFetcher())
    c.refresh_from_db()
    assert c.status == "captured"
    assert snap.entry_count == 1
    assert snap.is_open_dir is True
    assert snap.server_kind == "apache"
    assert snap.tls == {"sha256": "deadbeef", "self_signed": True}
    assert snap.final_url == "https://ex.com/files/"


@pytest.mark.django_db
def test_run_capture_returns_structured_dict_without_raw_body():
    data = run_capture("http://ex.com/files/", _ok_fetcher())
    assert data["http_status"] == 200
    assert data["server_kind"] == "apache"
    assert data["entry_count"] == 2
    assert data["is_open_dir"] is True
    assert data["title"].startswith("Index of")
    assert data["final_url"] == "http://ex.com/files/"
    assert "raw_html_sha256" in data and data["raw_html_sha256"]
    assert "body" not in data                 # raw HTML must never leave in the structured result


class _RaisingFetcher(Fetcher):
    """Fetcher whose fetch() must never be called; proves the scope guard
    short-circuits before any network access is attempted."""
    def fetch(self, url):
        raise AssertionError("fetch() must not be called for a blocked candidate")


@pytest.mark.django_db
def test_capture_blocks_private_ip_without_fetching():
    c = Candidate.objects.create(dedup_key="10.0.0.1/", url="http://10.0.0.1/", source="fake")
    snap = capture_candidate(c, fetcher=_RaisingFetcher())
    c.refresh_from_db()
    assert c.status == "error"
    assert "blocked" in snap.error
    assert snap.http_status is None
    assert Snapshot.objects.count() == 1


@pytest.mark.django_db
def test_ingest_capture_dict_creates_snapshot_from_dict():
    from opendir.capture.tier1 import ingest_capture_dict
    c = Candidate.objects.create(dedup_key="ex.com/d", url="http://ex.com/d/", source="fake")
    data = {
        "error": "", "http_status": 200, "final_url": "http://ex.com/d/",
        "headers": [("server", "nginx")], "server_banner": "nginx",
        "server_kind": "nginx", "title": "Index of /d", "is_open_dir": True,
        "listing_entries": [{"name": "a.zip", "href": "a.zip", "is_dir": False,
                             "size": None, "mtime": None, "path": "/d/a.zip"}],
        "entry_count": 1, "raw_html_sha256": "aa", "header_order_sha256": "bb",
        "template_sha256": "cc", "favicon_sha256": None, "tls": None,
    }
    snap = ingest_capture_dict(c, data)
    c.refresh_from_db()
    assert c.status == "captured" and c.last_captured_at is not None
    assert snap.is_open_dir is True and snap.entry_count == 1
    assert snap.server_kind == "nginx" and snap.final_url == "http://ex.com/d/"


@pytest.mark.django_db
def test_ingest_capture_dict_records_error():
    from opendir.capture.tier1 import ingest_capture_dict
    c = Candidate.objects.create(dedup_key="ex.com/e", url="http://ex.com/e/", source="fake")
    snap = ingest_capture_dict(c, {"error": "timeout", "http_status": None, "final_url": "http://ex.com/e/"})
    c.refresh_from_db()
    assert c.status == "error" and snap.error == "timeout"


class _FakeClock:
    def __init__(self): self.t = 0.0; self.slept = []
    def monotonic(self): return self.t
    def sleep(self, s): self.slept.append(s); self.t += s


@pytest.mark.django_db
def test_capture_modal_egress_throttles_per_host(monkeypatch):
    """The refactor that made capture_candidate's modal branch call
    _remote_capture(url, fetcher) must not have dropped per-host throttling --
    otherwise a `--egress modal` capture batch can hammer a host with no
    spacing between same-host requests."""
    import opendir.capture.tier1 as tier1

    canned = {
        "error": "", "http_status": 200, "final_url": "https://ex.com/files/",
        "headers": [("server", "Apache")], "server_banner": "Apache",
        "server_kind": "apache", "title": "Index of /files", "is_open_dir": True,
        "listing_entries": [], "entry_count": 0,
        "raw_html_sha256": "abc123", "header_order_sha256": "def456",
        "template_sha256": "789xyz", "favicon_sha256": None,
        "tls": None,
    }
    monkeypatch.setattr(tier1, "_default_remote_capture",
                        lambda url, user_agent, timeout, max_bytes, max_redirects: dict(canned))

    clock = _FakeClock()
    fetcher = Fetcher(egress="modal", min_interval=1.0, sleep=clock.sleep, monotonic=clock.monotonic)

    c1 = Candidate.objects.create(dedup_key="ex.com/files1", url="https://ex.com/files1/", source="fake")
    c2 = Candidate.objects.create(dedup_key="ex.com/files2", url="https://ex.com/files2/", source="fake")
    capture_candidate(c1, fetcher)
    capture_candidate(c2, fetcher)          # same host as c1: must be throttled
    assert clock.slept and abs(clock.slept[0] - 1.0) < 1e-6

    clock2 = _FakeClock()
    fetcher2 = Fetcher(egress="modal", min_interval=1.0, sleep=clock2.sleep, monotonic=clock2.monotonic)
    c3 = Candidate.objects.create(dedup_key="other.com/files", url="https://other.com/files/", source="fake")
    capture_candidate(c1, fetcher2)
    capture_candidate(c3, fetcher2)         # different host: must NOT be throttled
    assert clock2.slept == []
