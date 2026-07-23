import pytest
from opendir.models import Candidate, Snapshot
from opendir.infra.orchestrate import run_batch, select_candidate_urls
from opendir.infra.provision import DropletHandle, DropletConfig


def _cfg():
    return DropletConfig(name="t", region="nyc3", size="s", image="i",
                         ssh_key_fingerprints=["fp"], delete_token="del")


class _Deploy:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on
    def push_repo(self, ip, rd): self.calls.append("push")
    def setup_remote(self, ip): self.calls.append("setup")
    def run_worker(self, ip, urls, contact="", **kw):
        self.calls.append("run")
        if self.fail_on == "run":
            raise RuntimeError("worker boom")
    def pull_results(self, ip, dst): self.calls.append("pull"); return dst


def test_run_batch_tears_down_even_when_worker_fails():
    torn = []
    dep = _Deploy(fail_on="run")
    with pytest.raises(RuntimeError):
        run_batch(_cfg(), ["u"], "/repo", "/tmp/r.jsonl",
                  provision_fn=lambda c: DropletHandle(id=1, ip="1.2.3.4"),
                  deploy_mod=dep, ingest_fn=lambda p: None,
                  teardown_fn=lambda h: torn.append(h.id))
    assert torn == [1]                       # teardown ran in finally


def test_run_batch_keep_skips_teardown_and_returns_stats():
    torn = []
    dep = _Deploy()
    result = run_batch(_cfg(), ["u"], "/repo", "/tmp/r.jsonl",
                       provision_fn=lambda c: DropletHandle(id=1, ip="1.2.3.4"),
                       deploy_mod=dep, ingest_fn=lambda p: "STATS",
                       teardown_fn=lambda h: torn.append(h.id), keep=True)
    assert result == "STATS"
    assert torn == []
    assert dep.calls == ["push", "setup", "run", "pull"]


def test_run_batch_tears_down_on_success():
    torn = []
    dep = _Deploy()
    result = run_batch(_cfg(), ["u"], "/repo", "/tmp/r.jsonl",
                       provision_fn=lambda c: DropletHandle(id=2, ip="1.2.3.4"),
                       deploy_mod=dep, ingest_fn=lambda p: "OK",
                       teardown_fn=lambda h: torn.append(h.id))
    assert result == "OK" and torn == [2]
    assert dep.calls == ["push", "setup", "run", "pull"]


@pytest.mark.django_db
def test_select_candidate_urls_pending_vs_recapture():
    pend = Candidate.objects.create(dedup_key="p", url="http://p/", source="fake", status="pending")
    cap = Candidate.objects.create(dedup_key="c", url="http://c/", source="fake", status="captured")
    Snapshot.objects.create(candidate=cap, http_status=200, is_open_dir=True)
    assert select_candidate_urls(recapture=False, limit=50) == ["http://p/"]
    assert select_candidate_urls(recapture=True, limit=50) == ["http://c/"]
