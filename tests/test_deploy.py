import types
import pytest
from opendir.infra import deploy


class _Recorder:
    def __init__(self, returncodes=None):
        self.calls = []
        self._rc = list(returncodes or [])
    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        rc = self._rc.pop(0) if self._rc else 0
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="")


def test_wait_for_ssh_succeeds_when_ssh_returns_zero(monkeypatch):
    rec = _Recorder(returncodes=[1, 0])   # first probe fails, second succeeds
    monkeypatch.setattr(deploy, "_run", rec)
    slept = []
    deploy.wait_for_ssh("5.6.7.8", timeout=60, interval=5, sleep=lambda s: slept.append(s))
    assert len(rec.calls) == 2
    assert slept == [5]
    assert rec.calls[0][0][0] == "ssh"


def test_wait_for_ssh_times_out(monkeypatch):
    monkeypatch.setattr(deploy, "_run", _Recorder(returncodes=[1, 1, 1]))
    with pytest.raises(TimeoutError):
        deploy.wait_for_ssh("5.6.7.8", timeout=10, interval=5, sleep=lambda s: None)


def test_push_repo_uses_rsync_with_excludes(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(deploy, "_run", rec)
    deploy.push_repo("5.6.7.8", "/home/u/repo")
    rsync = [c for c, kw in rec.calls if c[0] == "rsync"][0]
    assert "--exclude" in rsync and ".env" in rsync and ".git" in rsync
    assert ".do_runs" in rsync
    assert rsync[-1] == "root@5.6.7.8:/opt/patefact/"


def test_run_worker_runs_as_worker_user_and_redirects_jsonl(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(deploy, "_run", rec)
    deploy.run_worker("5.6.7.8", ["http://a/", "http://b/"], contact="me@example.com")
    joined = " ".join(" ".join(c) for c, kw in rec.calls)
    assert "sudo -u worker" in joined
    assert "opendir.infra.worker" in joined
    assert "results.jsonl" in joined
    assert "OPENDIR_CONTACT=me@example.com" in joined
    assert "env OPENDIR_CONTACT=" in joined


def test_pull_results_scps_home(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(deploy, "_run", rec)
    out = deploy.pull_results("5.6.7.8", "/tmp/results.jsonl")
    assert out == "/tmp/results.jsonl"
    scp = [c for c, kw in rec.calls if c[0] == "scp"][0]
    assert scp[-2].endswith("results.jsonl") and scp[-1] == "/tmp/results.jsonl"
