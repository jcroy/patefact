import httpx
import pytest
from django.test import override_settings
from opendir.capture.fetcher import Fetcher, DEFAULT_USER_AGENT, build_user_agent

def _transport(handler):
    return httpx.MockTransport(handler)

def test_fetch_returns_body_and_ordered_headers():
    def handler(request):
        assert request.headers["user-agent"] == DEFAULT_USER_AGENT
        return httpx.Response(200, headers=[("Server", "nginx"), ("X-A", "1")],
                              text="<html>ok</html>")
    f = Fetcher(transport=_transport(handler))
    r = f.fetch("http://ex.com/")
    assert r.status == 200
    assert r.body == "<html>ok</html>"
    assert r.headers[0] == ("server", "nginx")
    assert r.error == ""

def test_fetch_captures_error_without_raising():
    def handler(request):
        raise httpx.ConnectError("boom")
    f = Fetcher(transport=_transport(handler))
    r = f.fetch("http://ex.com/")
    assert r.status is None
    assert "boom" in r.error

def test_proxy_egress_still_not_implemented():
    with pytest.raises(NotImplementedError):
        Fetcher(egress="proxy").fetch("http://ex.com/")

def test_fetch_caps_body_at_max_bytes():
    big = "a" * 100_000
    def handler(request):
        return httpx.Response(200, text=big)
    f = Fetcher(transport=httpx.MockTransport(handler), max_bytes=1000)
    r = f.fetch("http://ex.com/")
    assert len(r.body) <= 1000
    assert r.error == ""

def test_fetch_stops_reading_after_max_bytes():
    class CountingStream(httpx.SyncByteStream):
        def __init__(self, chunks):
            self.chunks = chunks
            self.yielded = 0
        def __iter__(self):
            for c in self.chunks:
                self.yielded += 1
                yield c
        def close(self):
            pass
    stream = CountingStream([b"a" * 500, b"b" * 500, b"c" * 500])
    def handler(request):
        return httpx.Response(200, stream=stream, headers={"content-type": "text/plain"})
    f = Fetcher(transport=httpx.MockTransport(handler), max_bytes=1000)
    r = f.fetch("http://ex.com/")
    assert len(r.body) == 1000          # exactly capped (500 + 500)
    assert stream.yielded == 2          # third chunk never pulled -> streaming stopped early
    assert r.error == ""

def test_user_agent_uses_configured_contact():
    with override_settings(OPENDIR_CONTACT="research@example.org"):
        ua = build_user_agent()
        assert "opt-out: research@example.org" in ua
        assert Fetcher().user_agent == ua   # Fetcher builds from settings when user_agent not passed

def test_redirect_to_private_ip_is_blocked_without_connecting():
    def handler(request):
        if request.url.host == "evil.example":
            return httpx.Response(302, headers={"location": "http://10.0.0.1/"})
        raise AssertionError(f"must not connect to {request.url.host}")  # 10.0.0.1 must never be requested
    f = Fetcher(transport=httpx.MockTransport(handler))
    r = f.fetch("http://evil.example/")
    assert r.status == 302
    assert "blocked redirect" in r.error
    assert "10.0.0.1" in r.error

def test_redirect_to_metadata_endpoint_blocked():
    def handler(request):
        if request.url.host == "start.example":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        raise AssertionError("must not connect to metadata endpoint")
    f = Fetcher(transport=httpx.MockTransport(handler))
    r = f.fetch("http://start.example/")
    assert "blocked redirect" in r.error

def test_public_redirect_is_followed():
    def handler(request):
        if request.url.host == "a.example":
            return httpx.Response(301, headers={"location": "http://b.example/x"})
        return httpx.Response(200, text="landed")
    f = Fetcher(transport=httpx.MockTransport(handler))
    r = f.fetch("http://a.example/")
    assert r.status == 200 and r.body == "landed"
    assert r.final_url == "http://b.example/x"


class FakeClock:
    def __init__(self): self.t = 0.0; self.slept = []
    def monotonic(self): return self.t
    def sleep(self, s): self.slept.append(s); self.t += s


def test_same_host_requests_are_spaced_by_min_interval():
    clock = FakeClock()
    def handler(request): return httpx.Response(200, text="ok")
    f = Fetcher(transport=httpx.MockTransport(handler), min_interval=1.0,
                sleep=clock.sleep, monotonic=clock.monotonic)
    f.fetch("http://ex.com/a")          # first request: no wait
    f.fetch("http://ex.com/b")          # same host: must wait ~1.0s
    assert clock.slept and abs(clock.slept[0] - 1.0) < 1e-6

def test_different_hosts_not_throttled():
    clock = FakeClock()
    def handler(request): return httpx.Response(200, text="ok")
    f = Fetcher(transport=httpx.MockTransport(handler), min_interval=1.0,
                sleep=clock.sleep, monotonic=clock.monotonic)
    f.fetch("http://a.com/")
    f.fetch("http://b.com/")
    assert clock.slept == []

def test_retries_on_503_then_succeeds():
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, headers={"retry-after": "2"}, text="busy")
        return httpx.Response(200, text="ok")
    clock = FakeClock()
    f = Fetcher(transport=httpx.MockTransport(handler), min_interval=0, max_retries=2,
                sleep=clock.sleep, monotonic=clock.monotonic)
    r = f.fetch("http://ex.com/")
    assert r.status == 200 and calls["n"] == 2
    assert 2.0 in clock.slept        # honored Retry-After

def test_retries_on_503_with_retry_after_zero_honors_zero_delay():
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, headers={"retry-after": "0"}, text="busy")
        return httpx.Response(200, text="ok")
    clock = FakeClock()
    f = Fetcher(transport=httpx.MockTransport(handler), min_interval=0, max_retries=2,
                sleep=clock.sleep, monotonic=clock.monotonic)
    r = f.fetch("http://ex.com/")
    assert r.status == 200 and calls["n"] == 2
    assert 0 in clock.slept          # honored explicit Retry-After: 0, not exponential backoff (2**0=1)

def test_retry_after_is_capped_to_bound_self_dos():
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, headers={"retry-after": "86400"}, text="busy")
        return httpx.Response(200, text="ok")
    clock = FakeClock()
    f = Fetcher(transport=httpx.MockTransport(handler), min_interval=0, max_retries=2,
                sleep=clock.sleep, monotonic=clock.monotonic)
    r = f.fetch("http://ex.com/")
    assert r.status == 200 and calls["n"] == 2
    assert 60.0 in clock.slept       # capped at MAX_BACKOFF, not the hostile 86400
    assert 86400 not in clock.slept

def test_fetch_blocks_initial_url_without_connecting():
    def handler(request):
        raise AssertionError(f"must not connect to {request.url.host}")
    f = Fetcher(transport=httpx.MockTransport(handler))
    r = f.fetch("http://127.0.0.1/")
    assert r.status is None
    assert "blocked" in r.error


def test_modal_egress_reconstructs_fetchresult():
    def fake_modal_fn(url, user_agent, timeout, max_bytes, max_redirects):
        return {"url": "http://ex.com/", "final_url": "http://ex.com/", "status": 200,
                "headers": [["server", "nginx"], ["x-a", "1"]],
                "body": "<html>ok</html>", "tls": None, "error": ""}
    f = Fetcher(egress="modal", modal_fn=fake_modal_fn)
    r = f.fetch("http://ex.com/")
    assert r.status == 200
    assert r.body == "<html>ok</html>"
    assert r.headers == [("server", "nginx"), ("x-a", "1")]
    assert r.error == ""


def test_modal_egress_throttles_per_host():
    clock = FakeClock()
    def fake_modal_fn(url, user_agent, timeout, max_bytes, max_redirects):
        return {"url": url, "final_url": url, "status": 200,
                "headers": [], "body": "ok", "tls": None, "error": ""}
    f = Fetcher(egress="modal", modal_fn=fake_modal_fn, min_interval=1.0,
                sleep=clock.sleep, monotonic=clock.monotonic)
    f.fetch("http://ex.com/a")          # first request: no wait
    f.fetch("http://ex.com/b")          # same host: must wait ~1.0s
    assert clock.slept and abs(clock.slept[0] - 1.0) < 1e-6

    clock2 = FakeClock()
    f2 = Fetcher(egress="modal", modal_fn=fake_modal_fn, min_interval=1.0,
                 sleep=clock2.sleep, monotonic=clock2.monotonic)
    f2.fetch("http://a.com/")
    f2.fetch("http://b.com/")
    assert clock2.slept == []


def test_modal_egress_captures_errors_without_raising():
    def fake_modal_fn(url, user_agent, timeout, max_bytes, max_redirects):
        raise RuntimeError("boom")
    f = Fetcher(egress="modal", modal_fn=fake_modal_fn)
    r = f.fetch("http://ex.com/")
    assert r.status is None
    assert "modal egress error" in r.error


def test_modal_egress_malformed_payload_returns_error():
    def fake_modal_fn(url, user_agent, timeout, max_bytes, max_redirects):
        return {"body": "x"}
    f = Fetcher(egress="modal", modal_fn=fake_modal_fn)
    r = f.fetch("http://ex.com/")
    assert r.status is None
    assert "modal egress error" in r.error
