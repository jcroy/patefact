import pytest
from opendir.discovery.base import Discovered, ingest_candidates
from opendir.models import Candidate


class FakeSource:
    name = "fake"
    def __init__(self, urls):
        self._urls = urls
    def fetch(self, since=None):
        for u in self._urls:
            yield Discovered(url=u, source=self.name, source_meta={"seed": u})


@pytest.mark.django_db
def test_ingest_creates_rows():
    n = ingest_candidates(FakeSource(["http://a.com/", "http://b.com/"]))
    assert n == 2
    assert Candidate.objects.count() == 2

@pytest.mark.django_db
def test_ingest_dedupes_across_scheme_and_slash():
    ingest_candidates(FakeSource(["http://a.com/x"]))
    n = ingest_candidates(FakeSource(["https://a.com/x/"]))
    assert n == 0
    assert Candidate.objects.count() == 1

@pytest.mark.django_db
def test_ingest_stores_normalized_url_and_meta():
    ingest_candidates(FakeSource(["HTTP://A.com"]))
    c = Candidate.objects.get()
    assert c.url == "http://a.com/"
    assert c.source == "fake"
    assert c.source_meta == {"seed": "HTTP://A.com"}


@pytest.mark.django_db
def test_ingest_skips_blocked_urls():
    n = ingest_candidates(FakeSource(["http://public.example/", "http://10.0.0.5/"]))
    assert n == 1
    assert Candidate.objects.count() == 1
    assert Candidate.objects.get().url == "http://public.example/"
