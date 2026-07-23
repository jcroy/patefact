from opendir.discovery.shodan import _url_from_match, ShodanSource


def test_url_from_match_plain_http_port_80():
    match = {"ip_str": "1.2.3.4", "port": 80}
    assert _url_from_match(match) == "http://1.2.3.4/"


def test_url_from_match_https_via_ssl_key_non_default_port():
    match = {"ip_str": "1.2.3.4", "port": 8443, "ssl": {}}
    assert _url_from_match(match) == "https://1.2.3.4:8443/"


def test_url_from_match_https_via_port_443():
    match = {"ip_str": "1.2.3.4", "port": 443}
    assert _url_from_match(match) == "https://1.2.3.4/"


def test_url_from_match_ipv6_brackets_with_non_default_port():
    match = {"ip_str": "2606:4700::1", "port": 8443, "ssl": {}}
    assert _url_from_match(match) == "https://[2606:4700::1]:8443/"


def test_url_from_match_missing_ip_str_returns_none():
    match = {"port": 80}
    assert _url_from_match(match) is None


def test_url_from_match_missing_port_returns_none():
    match = {"ip_str": "1.2.3.4"}
    assert _url_from_match(match) is None


MATCH_HTTP = {
    "ip_str": "203.0.113.10",
    "port": 80,
    "transport": "tcp",
    "asn": "AS52148",
    "org": "Example Org",
    "hostnames": ["example.com"],
    "location": {"country_code": "DE"},
    "product": "Apache httpd",
}

MATCH_HTTPS = {
    "ip_str": "203.0.113.11",
    "port": 8443,
    "transport": "tcp",
    "ssl": {"cert": {}},
    "asn": "AS52148",
    "org": "Example Org",
    "hostnames": [],
    "location": {"country_code": "DE"},
    "product": "nginx",
}


class FakeClient:
    def search(self, query, page):
        if page == 1:
            return {"matches": [MATCH_HTTP, MATCH_HTTPS]}
        return {"matches": []}


def test_source_yields_discovered_with_meta():
    src = ShodanSource(query='product:"Apache httpd"', client=FakeClient())
    out = list(src.fetch())
    assert src.name == "shodan"
    assert any(d.url == "http://203.0.113.10/" for d in out)
    d = next(x for x in out if x.url == "http://203.0.113.10/")
    assert d.source == "shodan"
    assert d.source_meta["ip"] == "203.0.113.10"
    assert d.source_meta["asn"] == "AS52148"
    assert d.source_meta["org"] == "Example Org"
    assert d.source_meta["country"] == "DE"


def test_source_yields_discovered_for_https_match():
    src = ShodanSource(query='product:"Apache httpd"', client=FakeClient())
    out = list(src.fetch())
    assert any(d.url == "https://203.0.113.11:8443/" for d in out)


class OneMatchThenEmptyClient:
    def __init__(self):
        self.calls = []

    def search(self, query, page):
        self.calls.append(page)
        if page == 1:
            return {"matches": [MATCH_HTTP]}
        return {"matches": []}


def test_source_stops_early_when_page_returns_no_matches():
    client = OneMatchThenEmptyClient()
    src = ShodanSource(query="x", client=client, max_pages=5)
    out = list(src.fetch())
    assert len(out) == 1
    assert client.calls == [1, 2]
