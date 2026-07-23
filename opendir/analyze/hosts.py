"""Anonymized per-host breakdown for reports/dashboards.

Groups per-directory findings by origin host (ports collapsed), ranks them
worst-first, and renders each as a pseudonymous ``Host NN`` row listing the
signal *types* present -- never the address. This is the safe way to convey
per-host texture ("this host leaks SQL dumps + credentials") in an artifact
that must not point at live victims.

Pure and address-free by construction: :func:`host_breakdown` takes plain
records (url, label, features, entries), uses the url only to group/count
ports, and emits no hostname, IP, port, or path in its output.
"""
from urllib.parse import urlsplit

from opendir.analyze.inventory import scan_names

# Human-readable, address-free signal names, ordered scariest-first so each
# host row leads with its worst exposure.
SIGNAL_LABELS = {
    "webshell": "⚠ webshell", "malware_tool": "⚠ offensive tooling",
    "priv_key": "private keys", "ssh_key": "SSH keys", "credential": "credential files",
    "env": ".env secrets", "sql_dump": "SQL dumps", "database": "database files",
    "personal_records": "personal-records files", "financial": "financial-data files",
    "cloud_creds": "cloud credentials", "auth_secrets": "auth secrets/tokens",
    "config": "config files", "git": ".git repo", "executable": "executables",
    "script": "scripts", "binary": "raw binaries", "backup": "backups",
    "capture": "packet captures", "vpn": "VPN configs",
    "vcs_source": "source-control dirs", "logs": "log files",
}
_SIGNAL_ORDER = list(SIGNAL_LABELS)
_SEV = {"malicious_staging": 0, "sensitive_exposure": 1,
        "intentional_public": 2, "benign_index": 3}
_VERDICT = {"malicious_staging": "malicious", "sensitive_exposure": "sensitive"}


def _signals_for(features, entries):
    sig = {k for k, v in (features.get("sensitive_hits") or {}).items() if v}
    sig |= {k for k, v in (features.get("payload_hits") or {}).items() if v}
    sig |= set(scan_names(entries or []).keys())
    return sig


def host_breakdown(records, *, flagged_only=True):
    """Collapse records to ranked, anonymized per-host rows.

    ``records``: iterable of dicts with keys ``url``, ``label``, ``features``,
    ``entries``. Returns ``(rows, total)`` where each row is
    ``{"verdict", "signals": [friendly, ...], "ports": int}`` and contains no
    address. ``total`` is the number of flagged hosts (rows is the full ranked
    list; slice for display).
    """
    groups: dict[str, dict] = {}
    for r in records:
        hk = urlsplit(r["url"]).hostname or r["url"]
        g = groups.setdefault(hk, {"label": "benign_index", "signals": set(), "ports": set()})
        g["signals"] |= _signals_for(r.get("features") or {}, r.get("entries"))
        g["ports"].add(urlsplit(r["url"]).port)
        if _SEV.get(r["label"], 9) < _SEV.get(g["label"], 9):
            g["label"] = r["label"]

    ranked = sorted(
        (g for g in groups.values()
         if not flagged_only or (g["label"] in _VERDICT and g["signals"])),
        key=lambda g: (_SEV.get(g["label"], 9), -len(g["signals"]), sorted(g["signals"])),
    )
    rows = [
        {
            "verdict": _VERDICT.get(g["label"], g["label"]),
            "signals": [SIGNAL_LABELS.get(k, k) for k in _SIGNAL_ORDER if k in g["signals"]],
            "ports": len([p for p in g["ports"] if p]) or 1,
        }
        for g in ranked
    ]
    return rows, len(rows)
