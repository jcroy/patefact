from opendir.discovery.normalize import normalize_url, dedup_key

def test_normalize_lowercases_host_and_scheme():
    assert normalize_url("HTTP://Example.COM/Path") == "http://example.com/Path"

def test_normalize_strips_default_port_and_fragment():
    assert normalize_url("http://ex.com:80/a#frag") == "http://ex.com/a"
    assert normalize_url("https://ex.com:443/") == "https://ex.com/"

def test_normalize_adds_root_path():
    assert normalize_url("http://ex.com") == "http://ex.com/"

def test_dedup_key_is_scheme_agnostic():
    assert dedup_key("http://ex.com/a/") == dedup_key("https://ex.com/a/")

def test_dedup_key_ignores_trailing_slash():
    assert dedup_key("http://ex.com/a") == dedup_key("http://ex.com/a/")

def test_dedup_key_keeps_nonstandard_port():
    assert dedup_key("http://ex.com:8080/a") == "ex.com:8080/a"

def test_normalize_keeps_ipv6_bracketed_with_nonstandard_port():
    assert normalize_url("http://[::1]:8080/a") == "http://[::1]:8080/a"

def test_normalize_ipv6_strips_default_port():
    assert normalize_url("https://[::1]:443/") == "https://[::1]/"

def test_dedup_key_keeps_ipv6_bracketed():
    assert dedup_key("http://[::1]:8080/a") == "[::1]:8080/a"

def test_normalize_preserves_query_string():
    assert normalize_url("http://ex.com/a?sort=name") == "http://ex.com/a?sort=name"

def test_dedup_key_distinguishes_distinct_queries():
    assert dedup_key("http://ex.com/a?x=1") != dedup_key("http://ex.com/a?x=2")
    assert dedup_key("http://ex.com/a/") == "ex.com/a"
