"""Droplet-side Tier-1 capture worker.

Runs INSIDE the disposable droplet. Reads URLs (one per line, from a file arg or
stdin), captures each with a LOCAL-egress Fetcher (requests originate from the
droplet's IP), and writes one JSON object per line to stdout. Tier-1 only: never
downloads file contents, never writes to a database.

Capture is I/O-bound (waiting on remote servers), so an optional thread pool
(OPENDIR_WORKER_CONCURRENCY) fans out many fetches at once for a near-linear
speedup on large batches. The per-host rate limit still holds — every host in a
batch is distinct, so concurrent fetches never target the same host.
"""
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor


def _ensure_django():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django
    from django.apps import apps
    if not apps.ready:
        django.setup()


def _capture_one(url, fetcher):
    """Capture a single URL. Returns the result dict, or None for a blank line.
    One bad host never raises out of here — it becomes an error record."""
    from opendir.capture.tier1 import run_capture
    url = url.strip()
    if not url:
        return None
    try:
        data = run_capture(url, fetcher)
    except Exception as exc:  # one bad host must not kill the batch
        data = {"error": f"worker exception: {exc}", "http_status": None, "final_url": url}
    data["url"] = url
    return data


def capture_all(urls, fetcher, out, concurrency: int = 1) -> None:
    if concurrency <= 1:
        for url in urls:
            data = _capture_one(url, fetcher)
            if data is None:
                continue
            out.write(json.dumps(data) + "\n")
            out.flush()
        return

    write_lock = threading.Lock()

    def work(url):
        data = _capture_one(url, fetcher)
        if data is None:
            return
        line = json.dumps(data) + "\n"
        with write_lock:          # serialize writes so JSONL lines never interleave
            out.write(line)
            out.flush()

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(work, urls))


def main(argv=None, out=None) -> None:
    _ensure_django()
    from opendir.capture.fetcher import Fetcher
    argv = sys.argv[1:] if argv is None else argv
    out = out or sys.stdout
    if argv:
        with open(argv[0]) as f:
            urls = f.readlines()
    else:
        urls = sys.stdin.readlines()
    concurrency = int(os.environ.get("OPENDIR_WORKER_CONCURRENCY", "1") or "1")
    fkwargs = {"egress": "local"}
    timeout = os.environ.get("OPENDIR_FETCH_TIMEOUT")
    if timeout:
        fkwargs["timeout"] = float(timeout)
    capture_all(urls, Fetcher(**fkwargs), out, concurrency=concurrency)


if __name__ == "__main__":
    main()
