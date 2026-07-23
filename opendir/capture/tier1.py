import hashlib
from urllib.parse import urlsplit
from django.utils import timezone

from opendir.models import Candidate, Snapshot
from opendir.capture.fetcher import Fetcher
from opendir.capture.parser import parse_autoindex
from opendir.capture.fingerprint import (
    header_order_hash, template_hash, favicon_sha256, fetch_tls,
)
from opendir.discovery.scope import is_blocked


def _server_banner(headers) -> str:
    for k, v in headers:
        if k == "server":
            return v[:512]
    return ""


def run_capture(url: str, fetcher: Fetcher) -> dict:
    """Perform the full Tier-1 capture (fetch + parse + fingerprint) using the
    given fetcher and return a plain dict of derived Snapshot fields.

    The raw HTML body is NEVER included in the returned dict -- only its
    sha256 and the structural/derived signatures survive. This function is
    called with a LOCAL-egress fetcher: under `--egress modal` it runs
    *inside* the Modal container (see modal_app.remote_capture), so the
    modal-vs-local decision belongs to the caller (capture_candidate), not
    here -- there's no need for a `!= "modal"` guard on the TLS fallback.
    """
    assert getattr(fetcher, "egress", "local") != "modal", \
        "run_capture must run with a local-egress fetcher (untrusted content is processed here)"

    result = fetcher.fetch(url)

    if result.error or result.status is None:
        return {
            "error": result.error or "no response",
            "http_status": result.status,
            "final_url": result.final_url,
        }

    listing = parse_autoindex(result.body, result.final_url)
    entries = [vars(e) for e in listing.entries]
    parsed = urlsplit(result.final_url)
    if result.tls is not None:
        tls = result.tls                      # captured through the egress (e.g. Modal) -- no local connection
    elif parsed.scheme == "https":
        tls = fetch_tls(parsed.hostname, parsed.port or 443)   # local egress: local cert grab is fine
    else:
        tls = None

    return {
        "error": "",
        "http_status": result.status,
        "final_url": result.final_url,
        "headers": result.headers,
        "server_banner": _server_banner(result.headers),
        "server_kind": listing.server_kind,
        "title": listing.title[:512],
        "is_open_dir": listing.is_open_dir,
        "listing_entries": entries,
        "entry_count": len(entries),
        "raw_html_sha256": hashlib.sha256(result.body.encode("utf-8", "surrogatepass")).hexdigest(),
        "header_order_sha256": header_order_hash(result.headers),
        "template_sha256": template_hash(result.body),
        "favicon_sha256": favicon_sha256(fetcher, result.final_url),
        "tls": tls,
    }


def _default_remote_capture(url: str, user_agent: str, timeout: float,
                            max_bytes: int, max_redirects: int) -> dict:
    """Invoke the deployed Modal `remote_capture` function.

    Module-level so tests can monkeypatch `opendir.capture.tier1._default_remote_capture`
    to inject a canned structured dict without touching Modal or the network.
    """
    import modal
    fn = modal.Function.from_name("opendir-fetch", "remote_capture")
    return fn.remote(url, user_agent, timeout, max_bytes, max_redirects)


def _remote_capture(url: str, fetcher: Fetcher) -> dict:
    """Run the ENTIRE capture (fetch+parse+fingerprint) in the egress location
    (Modal), so untrusted HTML never reaches the operator's machine -- only
    the structured result dict returns.
    """
    fetcher.throttle(url)          # politeness: space same-host requests even though the fetch itself runs remotely
    try:
        return _default_remote_capture(
            url, fetcher.user_agent, fetcher.timeout, fetcher.max_bytes, fetcher.max_redirects,
        )
    except Exception as exc:
        return {"error": f"modal capture error: {exc}", "http_status": None, "final_url": url}


def ingest_capture_dict(candidate: Candidate, data: dict) -> Snapshot:
    """Turn a run_capture()/worker result dict into a Snapshot and update the
    candidate's status. Shared by the local, Modal, and DO-JSONL ingest paths."""
    if data.get("error"):
        snap = Snapshot.objects.create(candidate=candidate, http_status=data.get("http_status"),
                                       final_url=data.get("final_url", ""), error=data["error"])
        candidate.status = "error"
        candidate.last_captured_at = timezone.now()
        candidate.save(update_fields=["status", "last_captured_at"])
        return snap

    snap = Snapshot.objects.create(
        candidate=candidate,
        http_status=data["http_status"],
        final_url=data["final_url"],
        headers=data["headers"],
        server_banner=data["server_banner"],
        server_kind=data["server_kind"],
        title=data["title"],
        is_open_dir=data["is_open_dir"],
        listing_entries=data["listing_entries"],
        entry_count=data["entry_count"],
        raw_html_sha256=data["raw_html_sha256"],
        header_order_sha256=data["header_order_sha256"],
        template_sha256=data["template_sha256"],
        favicon_sha256=data["favicon_sha256"],
        tls=data["tls"],
    )
    candidate.status = "captured"
    candidate.last_captured_at = timezone.now()
    candidate.save(update_fields=["status", "last_captured_at"])
    return snap


def capture_candidate(candidate: Candidate, fetcher: Fetcher | None = None) -> Snapshot:
    if is_blocked(candidate.url):
        snap = Snapshot.objects.create(candidate=candidate, http_status=None,
                                       error="blocked by scope policy")
        candidate.status = "error"
        candidate.last_captured_at = timezone.now()
        candidate.save(update_fields=["status", "last_captured_at"])
        return snap

    fetcher = fetcher or Fetcher()
    if getattr(fetcher, "egress", "local") == "modal":
        data = _remote_capture(candidate.url, fetcher)     # full capture runs in Modal
    else:
        data = run_capture(candidate.url, fetcher)          # full capture runs locally

    return ingest_capture_dict(candidate, data)
