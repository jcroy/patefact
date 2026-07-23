from dataclasses import dataclass, field
import threading
import time
import httpx
from django.conf import settings

from opendir.discovery.scope import is_blocked


def _parse_retry_after(headers) -> float | None:
    value = headers.get("retry-after")
    if value is None:
        return None
    try:
        return float(int(value.strip()))
    except (ValueError, TypeError):
        return None  # HTTP-date form not supported in v1


def build_user_agent(contact: str | None = None) -> str:
    contact = contact or getattr(settings, "OPENDIR_CONTACT", "unset")
    return (
        "patefact/0.1 "
        f"(+https://github.com/jcroy/patefact; research; opt-out: {contact})"
    )


DEFAULT_USER_AGENT = build_user_agent()

# One Fetcher processes an entire capture batch sequentially, so a hostile
# Retry-After (or an exponential-backoff blowup) must not be allowed to stall
# all remaining captures for hours -- cap the delay we'll actually sleep for.
MAX_BACKOFF = 60.0


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    tls: dict | None = None
    error: str = ""


class Fetcher:
    def __init__(self, egress: str = "local", user_agent: str | None = None,
                 timeout: float = 20.0, max_bytes: int = 5_000_000, transport=None,
                 max_redirects: int = 5, min_interval: float | None = None,
                 max_retries: int = 2, sleep=time.sleep, monotonic=time.monotonic,
                 modal_fn=None):
        self.egress = egress
        self.user_agent = user_agent or build_user_agent()
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._transport = transport
        self.max_redirects = max_redirects
        self.min_interval = (min_interval if min_interval is not None
                              else getattr(settings, "OPENDIR_MIN_INTERVAL", 1.0))
        self.max_retries = max_retries
        self._sleep = sleep
        self._monotonic = monotonic
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()   # guards _last for concurrent worker threads
        self._modal_fn = modal_fn

    def _throttle(self, host: str) -> None:
        # Thread-safe: the dict read/write happen under a lock, but the sleep does
        # NOT (holding the lock across sleep would serialize all hosts). The
        # per-host interval is preserved; distinct hosts (the common case in a
        # bulk batch) never wait on each other.
        with self._lock:
            last = self._last.get(host)
            wait = (self.min_interval - (self._monotonic() - last)) if last is not None else 0.0
        if wait > 0:
            self._sleep(wait)
        with self._lock:
            self._last[host] = self._monotonic()

    def throttle(self, url: str) -> None:
        """Enforce the per-host minimum interval before a request to `url`."""
        self._throttle(httpx.URL(url).host)

    def fetch(self, url: str) -> FetchResult:
        if self.egress == "modal":
            return self._fetch_via_modal(url)
        if self.egress != "local":
            raise NotImplementedError(f"egress={self.egress!r} not implemented in v1")
        headers = {"User-Agent": self.user_agent, "Accept-Encoding": "identity"}
        # Redirects are followed MANUALLY (follow_redirects=False) so every hop's
        # resolved target is checked against is_blocked() before we ever connect
        # to it. httpx's auto-follow would otherwise let a crawled (untrusted)
        # server 302 us to a private IP or cloud metadata endpoint, bypassing the
        # pre-fetch scope guard entirely.
        #
        # Residual risk (deferred): this still trusts DNS at connect time, so a
        # public hostname that resolves to a private IP (DNS rebinding) is NOT
        # caught here -- is_blocked() only inspects the URL's literal host/IP.
        # Closing that gap needs resolve-then-pin at connect time.
        current = url
        redirects = retries = 0
        try:
            # verify=False: we connect to open dirs BY IP, but their TLS certs are
            # issued for hostnames, so httpx's default verification rejects the
            # connection ("CERTIFICATE_VERIFY_FAILED: IP address mismatch"), which
            # would kill HTTPS capture outright. This is standard practice for
            # internet-measurement crawlers: we read the public listing regardless
            # of cert trust; actual certificate metadata is captured separately by
            # fetch_tls.
            with httpx.Client(timeout=self.timeout, follow_redirects=False,
                              transport=self._transport, headers=headers,
                              verify=False) as client:
                while True:
                    if is_blocked(current):
                        return FetchResult(url=url, final_url=current, status=None,
                                           error=f"blocked {current}")
                    host = httpx.URL(current).host
                    self._throttle(host)
                    with client.stream("GET", current) as resp:
                        if resp.status_code in (429, 503) and retries < self.max_retries:
                            retries += 1
                            delay = _parse_retry_after(resp.headers)
                            if delay is None:
                                delay = 2 ** (retries - 1)
                            delay = min(delay, MAX_BACKOFF)
                            self._sleep(delay)
                            continue                       # retry same url
                        if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                            if redirects >= self.max_redirects:
                                return FetchResult(url=url, final_url=current, status=None, error="too many redirects")
                            target = str(httpx.URL(current).join(resp.headers["location"]))
                            if is_blocked(target):
                                return FetchResult(url=url, final_url=current, status=resp.status_code,
                                                   error=f"blocked redirect to {target}")
                            current = target
                            redirects += 1
                            retries = 0                    # fresh retry budget per hop
                            continue
                        raw = bytearray()
                        for chunk in resp.iter_bytes():          # iter_bytes yields DECOMPRESSED bytes
                            raw.extend(chunk)
                            if len(raw) >= self.max_bytes:       # stop early: bounds memory to ~max_bytes + one chunk
                                del raw[self.max_bytes:]
                                break
                        # We request identity encoding and cap accumulated output at max_bytes. For hosts
                        # that honor Accept-Encoding (the vast majority) no decompression occurs, so memory
                        # is bounded to ~max_bytes. Residual risk: a host that forces Content-Encoding despite
                        # our request can make httpx expand a single chunk beyond max_bytes before this cap
                        # sees it. Fully bounding that requires manual bounded decompression (deferred).
                        body = bytes(raw).decode(resp.encoding or "utf-8", errors="replace")
                        ordered = [(k.lower(), v) for k, v in resp.headers.multi_items()]
                        return FetchResult(url=url, final_url=str(resp.url),
                                           status=resp.status_code, headers=ordered, body=body,
                                           error="")
        except httpx.HTTPError as exc:
            return FetchResult(url=url, final_url=url, status=None, error=str(exc))

    def _fetch_via_modal(self, url: str) -> FetchResult:
        # The HTTP request itself runs remotely (on Modal), but politeness
        # (per-host throttling) is still enforced locally so a capture batch
        # can't hammer a host just because the egress hop moved off-box.
        self.throttle(url)
        fn = self._modal_fn or _default_modal_fn
        try:
            payload = fn(url, self.user_agent, self.timeout, self.max_bytes, self.max_redirects)
            return FetchResult(url=payload["url"], final_url=payload["final_url"],
                               status=payload["status"],
                               headers=[tuple(h) for h in (payload.get("headers") or [])],
                               body=payload.get("body", ""), tls=payload.get("tls"),
                               error=payload.get("error", ""))
        except Exception as exc:
            return FetchResult(url=url, final_url=url, status=None,
                               error=f"modal egress error: {exc}")


def _default_modal_fn(url, user_agent, timeout, max_bytes, max_redirects):
    import modal
    fn = modal.Function.from_name("opendir-fetch", "remote_fetch")
    return fn.remote(url, user_agent, timeout, max_bytes, max_redirects)
