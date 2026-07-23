from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _clean(url: str):
    parts = urlsplit(url if "://" in url else "http://" + url)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    path = parts.path or "/"
    query = parts.query
    return scheme, host, port, path, query


def _netloc(host: str, port: int | None, scheme: str) -> str:
    # IPv6 literals lose their brackets via urlsplit().hostname, so they must
    # be re-bracketed here before any port is appended.
    if ":" in host:
        host = f"[{host}]"
    if port and port != _DEFAULT_PORTS.get(scheme):
        return f"{host}:{port}"
    return host


def normalize_url(url: str) -> str:
    scheme, host, port, path, query = _clean(url)
    netloc = _netloc(host, port, scheme)
    # Fragment is intentionally dropped; query is preserved as-is.
    return urlunsplit((scheme, netloc, path, query, ""))


def dedup_key(url: str) -> str:
    scheme, host, port, path, query = _clean(url)
    netloc = _netloc(host, port, scheme)
    path = path.rstrip("/")
    key = f"{netloc}{path}" if path else f"{netloc}/"
    # Distinct query strings are treated as distinct keys for now. A future
    # refinement could normalize autoindex sort-param queries (e.g. Apache's
    # ?C=N;O=A directory-sort params) so they don't fragment the dedup space.
    if query:
        key = f"{key}?{query}"
    return key
