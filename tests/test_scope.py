import pytest
from django.test import override_settings
from opendir.discovery.scope import is_blocked

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.1.1/",
    "http://[::1]/", "http://example.gov/", "http://army.mil/", "http://not a url",
    "http://localhost/", "http://localhost:6379/", "http://foo.localhost/",
    "http://printer.local/", "http://metadata.google.internal/", "http://x.internal/",
])
def test_blocked(url):
    assert is_blocked(url) is True

@pytest.mark.parametrize("url", [
    "http://8.8.8.8/", "http://1.2.3.4:8443/", "http://example.com/files/",
    "http://sub.example.com/", "http://mylocalsite.com/",
])
def test_allowed(url):
    assert is_blocked(url) is False

def test_extra_cidr_blocked():
    with override_settings(OPENDIR_BLOCKED_CIDRS=("203.0.113.0/24",)):
        assert is_blocked("http://203.0.113.9/") is True

@pytest.mark.parametrize("url", [
    "http://2130706433/",      # bare decimal -> 127.0.0.1
    "http://0x7f000001/",      # hex -> 127.0.0.1
    "http://017700000001/",    # octal -> 127.0.0.1
    "http://0177.0.0.1/",      # zero-padded octal dotted -> 127.0.0.1
    "http://127.1/",           # short dotted -> 127.0.0.1
])
def test_blocked_numeric_ip_evasions(url):
    assert is_blocked(url) is True

def test_underscore_host_allowed():
    assert is_blocked("http://_dmarc.example.com/") is False

@pytest.mark.parametrize("url", [
    "http://127.0.0.1./",
    "http://169.254.169.254./",
    "http://metadata.google.internal./",
    "http://localhost./",
    "http://example.gov./",
])
def test_blocked_trailing_dot_bypass(url):
    assert is_blocked(url) is True

def test_allowed_trailing_dot_fqdn_public_host():
    assert is_blocked("http://example.com./") is False
