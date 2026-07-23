import ipaddress
import re
from urllib.parse import urlsplit
from django.conf import settings

# Hostnames/IPs only ever contain these characters. Anything else (spaces,
# stray text after a bad scheme, etc.) means urlsplit guessed rather than
# parsed, so we treat it the same as "no host" -> blocked.
_VALID_HOST_RE = re.compile(r"^[a-z0-9._\-:]+$")   # allow underscore too (e.g. _dmarc labels)
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]+|[0-9]+)$")

def _host(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return host if _VALID_HOST_RE.match(host) else ""

def _reserved(ip) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def _numeric_evasion(host: str) -> bool:
    # Reached only when ipaddress could NOT parse host as a standard IP.
    # OS resolvers still accept these numeric encodings -> block them.
    if _NUMERIC_LABEL.match(host):                       # bare int or 0xhex
        return True
    if "." in host:
        parts = host.split(".")
        if parts and all(p != "" and _NUMERIC_LABEL.match(p) for p in parts):
            return True                                  # 127.1, 0177.0.0.1, etc.
    return False

def is_blocked(url: str) -> bool:
    host = _host(url)
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:                                   # standard IP literal
        if _reserved(ip):
            return True
        for cidr in getattr(settings, "OPENDIR_BLOCKED_CIDRS", ()):
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass
        return False
    if _numeric_evasion(host):                           # numeric-encoded IP evasion
        return True
    for suf in getattr(settings, "OPENDIR_BLOCKED_SUFFIXES", (".gov", ".mil", ".localhost", ".local", ".internal")):
        if host == suf.lstrip(".") or host.endswith(suf):
            return True
    return False
