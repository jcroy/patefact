"""DB-facing payload-hashing service.

Bridges the download-safe URL selection in ``opendir.payload.select`` to the
``PayloadHash`` model: given a flagged Snapshot, selects the allowlisted
executable/script URLs from its listing, hashes them (by default, remotely
in Modal so untrusted bytes never touch the operator's machine), and
persists one append-only PayloadHash row per result.
"""

from opendir.models import PayloadHash, Snapshot
from opendir.payload.select import select_payload_urls


def _default_remote_hash(urls: list[str], user_agent: str, timeout: float, max_bytes: int) -> list[dict]:
    """Invoke the deployed Modal `remote_hash_payloads` function.

    Module-level so tests can monkeypatch `opendir.payload.service._default_remote_hash`
    to inject canned hash results without touching Modal or the network.
    """
    import modal
    fn = modal.Function.from_name("opendir-fetch", "remote_hash_payloads")
    return fn.remote(urls, user_agent, timeout, max_bytes)


def hash_payloads_for_snapshot(
    snapshot: Snapshot,
    *,
    remote_hash=None,
    user_agent: str = "patefact/0.1",
    timeout: float = 20.0,
    max_bytes: int = 20_000_000,
    max_files: int = 50,
) -> list[PayloadHash]:
    """Hash the allowlisted payload files referenced in a Snapshot's listing.

    Callers are expected to filter to flagged (sensitive/malicious) Snapshots
    themselves (see the ``hash_payloads`` management command); this function
    does not check that itself. Only URLs returned by ``select_payload_urls``
    are ever passed to the hasher -- media/archive/document/data files are
    never selected, so this can never send CSAM/PII-bearing content to Modal.
    """
    selected = select_payload_urls(snapshot.listing_entries, snapshot.candidate.url, max_files)
    if not selected:
        return []

    name_by_url = {entry["url"]: entry["name"] for entry in selected}
    urls = [entry["url"] for entry in selected]

    hasher = remote_hash or _default_remote_hash
    results = hasher(urls, user_agent, timeout, max_bytes)

    rows = []
    for result in results:
        rows.append(
            PayloadHash.objects.create(
                snapshot=snapshot,
                name=name_by_url.get(result["url"], ""),
                url=result["url"],
                sha256=result.get("sha256", ""),
                md5=result.get("md5", ""),
                tlsh=result.get("tlsh") or "",
                size=result.get("size", 0),
                error=result.get("error", ""),
            )
        )
    return rows
