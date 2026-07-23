from opendir.discovery.censys import _urls_from_host, CensysSource

HOST = {
    "ip": "1.2.3.4",
    "autonomous_system": {"asn": 64500, "name": "EXAMPLE"},
    "services": [
        {"port": 80, "service_name": "HTTP", "transport_protocol": "TCP"},
        {"port": 8443, "service_name": "HTTP", "extended_service_name": "HTTPS",
         "transport_protocol": "TCP"},
        {"port": 22, "service_name": "SSH", "transport_protocol": "TCP"},
    ],
}

def test_urls_from_host_extracts_http_services_only():
    urls = _urls_from_host(HOST)
    assert "http://1.2.3.4/" in urls
    assert "https://1.2.3.4:8443/" in urls
    assert all("22" not in u for u in urls)


IPV6_HOST = {
    "ip": "2606:4700::1",
    "services": [
        {"port": 8443, "service_name": "HTTP", "extended_service_name": "HTTPS",
         "transport_protocol": "TCP"},
    ],
}


def test_urls_from_host_brackets_ipv6_with_non_default_port():
    urls = _urls_from_host(IPV6_HOST)
    assert urls == ["https://[2606:4700::1]:8443/"]


def test_urls_from_host_brackets_ipv6_with_default_port():
    host = {
        "ip": "2606:4700::1",
        "services": [
            {"port": 443, "service_name": "HTTP", "extended_service_name": "HTTPS",
             "transport_protocol": "TCP"},
        ],
    }
    urls = _urls_from_host(host)
    assert urls == ["https://[2606:4700::1]/"]


def test_urls_from_host_skips_service_missing_port():
    host = {
        "ip": "1.2.3.4",
        "services": [
            {"service_name": "HTTP", "transport_protocol": "TCP"},
        ],
    }
    assert _urls_from_host(host) == []


class FakeClient:
    def search(self, query, per_page, pages):
        return [[HOST]]  # censys returns pages of lists of hosts

def test_source_yields_discovered_with_meta():
    src = CensysSource(query='services.http.response.html_title:"Index of /"', client=FakeClient())
    out = list(src.fetch())
    assert src.name == "censys"
    assert any(d.url == "http://1.2.3.4/" for d in out)
    d = next(x for x in out if x.url == "http://1.2.3.4/")
    assert d.source == "censys"
    assert d.source_meta["ip"] == "1.2.3.4"
    assert d.source_meta["asn"] == 64500
