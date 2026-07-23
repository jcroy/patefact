"""End-to-end DO capture batch orchestration (home-side).

Selects candidate URLs, provisions a droplet, deploys + runs the worker, pulls
results, ingests them, and always destroys the droplet (unless keep=True). The
seams (provision_fn/deploy_mod/ingest_fn/teardown_fn) are injectable for tests.
"""
from opendir.models import Candidate, Snapshot
from opendir.infra import deploy as _deploy
from opendir.infra.provision import provision as _provision, teardown as _teardown
from opendir.infra.ingest import ingest_jsonl as _ingest_jsonl


def select_candidate_urls(recapture: bool, limit: int) -> list:
    if recapture:
        open_ids = (Snapshot.objects.filter(is_open_dir=True)
                    .values_list("candidate_id", flat=True).distinct())
        qs = Candidate.objects.filter(id__in=list(open_ids)).order_by("first_seen")
    else:
        qs = Candidate.objects.filter(status="pending").order_by("first_seen")
    return list(qs[:limit].values_list("url", flat=True))


def run_batch(cfg, urls, repo_dir, results_path, *,
              provision_fn=_provision, deploy_mod=_deploy,
              ingest_fn=_ingest_jsonl, teardown_fn=_teardown, keep=False, contact="",
              concurrency=1, fetch_timeout=None):
    handle = provision_fn(cfg)
    try:
        deploy_mod.push_repo(handle.ip, repo_dir)
        deploy_mod.setup_remote(handle.ip)
        deploy_mod.run_worker(handle.ip, urls, contact=contact,
                              concurrency=concurrency, fetch_timeout=fetch_timeout)
        deploy_mod.pull_results(handle.ip, results_path)
        return ingest_fn(results_path)
    finally:
        if not keep:
            teardown_fn(handle)
