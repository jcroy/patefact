import os
from typing import Iterable
from opendir.discovery.base import Discovered

_HTTP_NAMES = {"HTTP", "HTTPS"}


def _is_https(service: dict) -> bool:
    ext = (service.get("extended_service_name") or "").upper()
    return ext == "HTTPS" or service.get("port") == 443


def _urls_from_host(host: dict) -> list[str]:
    ip = host.get("ip")
    urls = []
    for svc in host.get("services", []):
        name = (svc.get("service_name") or "").upper()
        ext = (svc.get("extended_service_name") or "").upper()
        if name not in _HTTP_NAMES and ext not in _HTTP_NAMES:
            continue
        port = svc.get("port")
        if port is None:
            # HTTP(S) service records are expected to carry a port; skip
            # malformed entries rather than emit "host:None".
            continue
        scheme = "https" if _is_https(svc) else "http"
        default = 443 if scheme == "https" else 80
        host_part = f"[{ip}]" if ip and ":" in ip else ip
        netloc = host_part if port == default else f"{host_part}:{port}"
        urls.append(f"{scheme}://{netloc}/")
    return urls


class CensysSource:
    name = "censys"

    def __init__(self, query: str, per_page: int = 100, max_pages: int = 5, client=None):
        self.query = query
        self.per_page = per_page
        self.max_pages = max_pages
        self._client = client

    def _get_client(self):
        if self._client is not None:
            return self._client
        from censys.search import CensysHosts  # imported lazily so tests need no creds
        return CensysHosts(
            api_id=os.environ.get("CENSYS_API_ID"),
            api_secret=os.environ.get("CENSYS_API_SECRET"),
        )

    def fetch(self, since=None) -> Iterable[Discovered]:
        client = self._get_client()
        for page in client.search(self.query, per_page=self.per_page, pages=self.max_pages):
            for host in page:
                asn = (host.get("autonomous_system") or {}).get("asn")
                for url in _urls_from_host(host):
                    yield Discovered(
                        url=url,
                        source=self.name,
                        source_meta={"ip": host.get("ip"), "asn": asn},
                    )
