"""Tests for the anonymized per-host breakdown (opendir.analyze.hosts)."""
from opendir.analyze.hosts import host_breakdown


def _rec(url, label, sensitive=None, payload=None, entries=None):
    return {
        "url": url,
        "label": label,
        "features": {"sensitive_hits": sensitive or {}, "payload_hits": payload or {}},
        "entries": entries or [],
    }


def test_ranks_malicious_first_then_by_signal_count():
    records = [
        _rec("http://a.example/", "sensitive_exposure", sensitive={"env": 1}),
        _rec("http://b.example/", "malicious_staging", payload={"webshell": 1}),
        _rec("http://c.example/", "sensitive_exposure", sensitive={"env": 1, "git": 1, "sql_dump": 1}),
    ]
    rows, total = host_breakdown(records)
    assert total == 3
    assert rows[0]["verdict"] == "malicious"            # b first (most severe)
    assert len(rows[1]["signals"]) == 3                 # c (3 signals) before a (1)
    assert rows[2]["verdict"] == "sensitive" and len(rows[2]["signals"]) == 1   # a last


def test_collapses_ports_of_one_host():
    records = [
        _rec(f"http://h.example:{p}/", "sensitive_exposure", sensitive={"env": 1})
        for p in (8080, 8081, 9000)
    ]
    rows, total = host_breakdown(records)
    assert total == 1                     # one origin, three ports
    assert rows[0]["ports"] == 3


def test_benign_excluded_when_flagged_only():
    records = [
        _rec("http://x.example/", "benign_index"),
        _rec("http://y.example/", "intentional_public"),
        _rec("http://z.example/", "sensitive_exposure", sensitive={"env": 1}),
    ]
    rows, total = host_breakdown(records)
    assert total == 1
    assert rows[0]["verdict"] == "sensitive"


def test_output_contains_no_address():
    """Safety invariant: no hostname/IP/port/path may appear in the output."""
    records = [
        _rec("http://203.0.113.44:8443/uniquepath/", "malicious_staging",
             payload={"webshell": 1}, sensitive={"env": 1}),
        _rec("https://targethost.zzqdomain/leakzone/", "sensitive_exposure",
             sensitive={"sql_dump": 1, "credential": 1}),
    ]
    rows, _ = host_breakdown(records)
    blob = repr(rows)
    for leak in ("203.0.113.44", "8443", "targethost", "zzqdomain", "uniquepath", "leakzone"):
        assert leak not in blob


def test_friendly_signal_ordering_worst_first():
    records = [_rec("http://a.example/", "sensitive_exposure",
                    sensitive={"config": 1, "priv_key": 1, "env": 1})]
    rows, _ = host_breakdown(records)
    # priv_key (private keys) is scarier than env than config -> appears earlier
    sig = rows[0]["signals"]
    assert sig.index("private keys") < sig.index(".env secrets") < sig.index("config files")
