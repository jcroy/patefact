import os
from typing import Iterable

import httpx

from opendir.discovery.base import Discovered

SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"


def _url_from_match(match: dict) -> str | None:
    ip = match.get("ip_str")
    if not ip:
        return None
    port = match.get("port")
    if port is None:
        # Malformed match missing a port; skip rather than emit "host:None".
        return None
    https = ("ssl" in match) or (port == 443)
    scheme = "https" if https else "http"
    default = 443 if https else 80
    host_part = f"[{ip}]" if ":" in ip else ip
    netloc = host_part if port == default else f"{host_part}:{port}"
    return f"{scheme}://{netloc}/"


class _HttpxShodanClient:
    """Thin wrapper over the Shodan REST search endpoint, used lazily so
    tests can inject a fake client and need no network or API key."""

    def __init__(self, api_key: str | None):
        self.api_key = api_key

    def search(self, query: str, page: int) -> dict:
        response = httpx.get(
            SHODAN_SEARCH_URL,
            params={"key": self.api_key, "query": query, "page": page},
        )
        response.raise_for_status()
        return response.json()


class ShodanSource:
    name = "shodan"

    def __init__(self, query: str, api_key: str | None = None, max_pages: int = 1, client=None):
        self.query = query
        self.api_key = api_key
        self.max_pages = max_pages
        self._client = client

    def _get_client(self):
        if self._client is not None:
            return self._client
        return _HttpxShodanClient(self.api_key or os.environ.get("SHODAN_API_KEY"))

    def fetch(self, since=None) -> Iterable[Discovered]:
        client = self._get_client()
        for page in range(1, self.max_pages + 1):
            result = client.search(self.query, page)
            matches = result.get("matches") or []
            if not matches:
                break
            for match in matches:
                url = _url_from_match(match)
                if url is None:
                    continue
                location = match.get("location") or {}
                yield Discovered(
                    url=url,
                    source=self.name,
                    source_meta={
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "asn": match.get("asn"),
                        "org": match.get("org"),
                        "hostnames": match.get("hostnames"),
                        "country": location.get("country_code"),
                        "product": match.get("product"),
                    },
                )
