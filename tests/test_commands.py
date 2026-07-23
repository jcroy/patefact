import httpx
import pytest
from io import StringIO
from django.core.management import call_command
from opendir.models import Candidate

LISTING = "<html><title>Index of /</title><a href='f.txt'>f.txt</a></html>"

@pytest.mark.django_db
def test_capture_command_processes_pending(monkeypatch):
    Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/", source="fake")
    def handler(request):
        return httpx.Response(200, headers=[("Server", "nginx")], text=LISTING)
    import opendir.management.commands.capture as capture_cmd
    from opendir.capture.fetcher import Fetcher
    monkeypatch.setattr(capture_cmd, "Fetcher", lambda *a, **k: Fetcher(transport=httpx.MockTransport(handler)))
    out = StringIO()
    call_command("capture", "--limit", "5", stdout=out)
    assert Candidate.objects.get().status == "captured"
    assert "captured" in out.getvalue()

@pytest.mark.django_db
def test_capture_command_continues_after_per_item_failure(monkeypatch):
    Candidate.objects.create(dedup_key="ex.com/a", url="http://ex.com/a/", source="fake")
    Candidate.objects.create(dedup_key="ex.com/b", url="http://ex.com/b/", source="fake")
    import opendir.management.commands.capture as capture_cmd

    def fake_capture_candidate(c, fetcher=None):
        if c.url.endswith("/a/"):
            raise RuntimeError("boom")
        c.status = "captured"
        c.save(update_fields=["status"])
        class FakeSnap:
            entry_count = 0
        return FakeSnap()

    monkeypatch.setattr(capture_cmd, "capture_candidate", fake_capture_candidate)
    out = StringIO()
    err = StringIO()
    call_command("capture", "--limit", "5", stdout=out, stderr=err)
    assert "done" in out.getvalue()
    assert "FAILED" in err.getvalue()
    assert Candidate.objects.get(url="http://ex.com/b/").status == "captured"

@pytest.mark.django_db
def test_capture_command_egress_flag_threads_to_fetcher(monkeypatch):
    Candidate.objects.create(dedup_key="ex.com/", url="http://ex.com/", source="fake")
    import opendir.management.commands.capture as capture_cmd
    from opendir.capture.fetcher import Fetcher
    seen = {}
    def fake_fetcher(*a, **k):
        seen["egress"] = k.get("egress")
        return Fetcher(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, headers=[("Server", "nginx")], text=LISTING)))
    monkeypatch.setattr(capture_cmd, "Fetcher", fake_fetcher)
    call_command("capture", "--egress", "modal", "--limit", "1", stdout=StringIO())
    assert seen["egress"] == "modal"

@pytest.mark.django_db
def test_discover_command_uses_injected_source(monkeypatch):
    from opendir.discovery.base import Discovered
    import opendir.management.commands.discover as disc
    class FakeSource:
        name = "censys"
        def __init__(self, **kw): pass
        def fetch(self, since=None):
            yield Discovered(url="http://new.com/", source="censys", source_meta={})
    monkeypatch.setattr(disc, "CensysSource", FakeSource)
    out = StringIO()
    call_command("discover", "--source", "censys", "--query", "x", stdout=out)
    assert Candidate.objects.filter(url="http://new.com/").exists()
    assert "1" in out.getvalue()

@pytest.mark.django_db
def test_discover_command_uses_injected_shodan_source(monkeypatch):
    from opendir.discovery.base import Discovered
    import opendir.management.commands.discover as disc
    class FakeShodanSource:
        name = "shodan"
        def __init__(self, **kw): pass
        def fetch(self, since=None):
            yield Discovered(url="http://shodan-new.com/", source="shodan", source_meta={})
    monkeypatch.setattr(disc, "ShodanSource", FakeShodanSource)
    out = StringIO()
    call_command("discover", "--source", "shodan", "--query", "x", stdout=out)
    assert Candidate.objects.filter(url="http://shodan-new.com/").exists()
    assert "1" in out.getvalue()
