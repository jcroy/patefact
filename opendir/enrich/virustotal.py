"""VirusTotal enrichment -- LOOKUP ONLY.

Looks up the existing public VirusTotal report for a file hash via a plain
GET against the v3 "files" endpoint. This module must never submit, scan,
or upload a file/URL to VirusTotal: doing so would make a (possibly
sensitive) sample's contents public. Only ``lookup_hash`` exists here, and
it only ever issues a GET to ``.../files/{sha256}``.
"""

import httpx
from django.conf import settings

VT_FILES_URL = "https://www.virustotal.com/api/v3/files/{sha256}"


def _default_client(url: str, headers: dict):
    """GET the given VT URL. Never POST/submit -- see module docstring."""
    return httpx.get(url, headers=headers)


def lookup_hash(sha256: str, *, client=None) -> dict:
    """Look up an existing VirusTotal report for ``sha256`` (GET, read-only).

    ``client`` is an injectable callable ``client(url, headers) ->
    response-like`` (an object with ``.status_code`` and ``.json()``),
    letting tests supply a fake with no network access or API key. When
    omitted, a real (GET-only) httpx call is made using ``settings.VT_API_KEY``.

    Returns:
      - HTTP 200: ``{"found": True, "malicious": int, "suspicious": int,
        "total": int, "type": str, "name": str}``.
      - HTTP 404 (no report on file): ``{"found": False}``.
      - Any other status: ``{"found": False, "error": f"vt {status}"}``.
    """
    get = client or _default_client
    url = VT_FILES_URL.format(sha256=sha256)
    headers = {"x-apikey": settings.VT_API_KEY}
    try:
        response = get(url, headers=headers)
        if response.status_code == 404:
            return {"found": False}
        if response.status_code != 200:
            return {"found": False, "error": f"vt {response.status_code}"}
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        # transient network/timeout or malformed JSON — record and move on so a
        # single failure doesn't abort a whole batch (and won't retry forever).
        return {"found": False, "error": str(exc)}

    data = body.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "type": attributes.get("type_description", ""),
        "name": attributes.get("meaningful_name", ""),
    }
