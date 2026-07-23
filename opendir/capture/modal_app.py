"""Modal Tier-1 egress for patefact.

Runs the local Fetcher inside a disposable Modal container so open-directory
requests originate from Modal's infrastructure, not the operator's IP.

Deploy:  uv run modal deploy opendir/capture/modal_app.py
Then Fetcher(egress="modal") invokes the deployed `remote_fetch` via
modal.Function.from_name("opendir-fetch", "remote_fetch").

`remote_capture` runs the ENTIRE Tier-1 capture (fetch + parse + fingerprint)
inside Modal too, so under `--egress modal` the operator's machine never
receives or processes untrusted HTML -- only the structured result dict
(no raw body) crosses back. opendir.capture.tier1.capture_candidate calls it
via modal.Function.from_name("opendir-fetch", "remote_capture").
"""
import modal

app = modal.App("opendir-fetch")


def _ensure_django():
    import os
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django
    from django.apps import apps
    if not apps.ready:
        django.setup()


image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        "httpx>=0.27", "django>=5.0", "selectolax>=0.3",
        "cryptography>=42", "python-dotenv>=1.0",
        # django.setup() loads the configured DB backend module (postgresql)
        # even though fetch() never queries the DB, so the driver must be present.
        "psycopg[binary]>=3.1",
        "python-tlsh>=4.5",
    )
    .add_local_python_source("opendir", "config")
)


@app.function(image=image)
def remote_fetch(url: str, user_agent: str, timeout: float,
                 max_bytes: int, max_redirects: int) -> dict:
    """Run the local-egress Fetcher inside Modal; return asdict(FetchResult)."""
    from dataclasses import asdict
    from urllib.parse import urlsplit
    _ensure_django()
    from opendir.capture.fetcher import Fetcher
    from opendir.capture.fingerprint import fetch_tls
    result = Fetcher(
        egress="local", min_interval=0, user_agent=user_agent,
        timeout=timeout, max_bytes=max_bytes, max_redirects=max_redirects,
    ).fetch(url)
    d = asdict(result)
    if not result.error:
        parsed = urlsplit(result.final_url)
        if parsed.scheme == "https":
            # capture the cert from within Modal too, so the whole capture leaves from Modal's IP
            d["tls"] = fetch_tls(parsed.hostname, parsed.port or 443)
    return d


@app.function(image=image)
def remote_capture(url: str, user_agent: str, timeout: float,
                   max_bytes: int, max_redirects: int) -> dict:
    """Run the FULL Tier-1 capture (fetch + parse + fingerprint) inside Modal
    and return the structured Snapshot-field dict produced by
    opendir.capture.tier1.run_capture -- never the raw HTML body. This is
    what makes `--egress modal` keep untrusted HTML off the operator's
    machine entirely: parsing/fingerprinting happen here, in the disposable
    container, not after the result comes back.
    """
    _ensure_django()
    from opendir.capture.tier1 import run_capture
    from opendir.capture.fetcher import Fetcher
    fetcher = Fetcher(
        egress="local", min_interval=0, user_agent=user_agent,
        timeout=timeout, max_bytes=max_bytes, max_redirects=max_redirects,
    )
    return run_capture(url, fetcher)


@app.function(image=image)
def remote_hash_payloads(urls: list[str], user_agent: str, timeout: float, max_bytes: int) -> list[dict]:
    """Download each URL's raw bytes IN Modal, hash-and-discard. Returns hashes only.

    Safety: only the caller-selected allowlist of URLs is passed in; this never
    executes anything, never follows redirects, caps size, and discards all bytes.
    """
    import hashlib
    import httpx
    _ensure_django()
    from opendir.discovery.scope import is_blocked

    results = []
    for url in urls:
        rec = {"url": url, "sha256": "", "md5": "", "tlsh": None, "size": 0, "error": ""}
        try:
            if is_blocked(url):
                rec["error"] = "blocked"
                results.append(rec); continue
            headers = {"User-Agent": user_agent, "Accept-Encoding": "identity"}
            with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers, verify=False) as client:
                with client.stream("GET", url) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        rec["error"] = "redirect (skipped)"
                        results.append(rec); continue
                    if resp.status_code != 200:
                        rec["error"] = f"http {resp.status_code}"
                        results.append(rec); continue
                    raw = bytearray()
                    too_large = False
                    for chunk in resp.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > max_bytes:
                            too_large = True
                            break
                    if too_large:
                        rec["error"] = "too_large"
                        results.append(rec); continue
                    data = bytes(raw)
                    rec["size"] = len(data)
                    rec["sha256"] = hashlib.sha256(data).hexdigest()
                    rec["md5"] = hashlib.md5(data).hexdigest()
                    try:
                        import tlsh
                        rec["tlsh"] = tlsh.hash(data) or None
                    except Exception:
                        rec["tlsh"] = None
                    del raw, data
        except Exception as exc:
            rec["error"] = str(exc)
        results.append(rec)
    return results
