"""Tests for the per-host file inventory (opendir.analyze.file_listing).

The safety invariants (no address, no data-file name in output) are the point
of this module -- they get the most scrutiny.
"""
import pytest

from opendir.analyze.file_listing import host_token, host_file_inventory

SALT = "test-secret-salt"


def _f(name, size=None, mtime=None):
    return {"name": name, "href": name, "is_dir": False, "size": size, "mtime": mtime}


def _d(name):
    return {"name": name, "href": name, "is_dir": True, "size": None, "mtime": None}


def _rec(url, label, entries):
    return {"url": url, "label": label, "entries": entries}


# ---- host_token -----------------------------------------------------------

def test_host_token_is_stable_and_salted():
    a = host_token("203.0.113.44", SALT)
    assert a == host_token("203.0.113.44", SALT)         # stable
    assert a != host_token("203.0.113.44", "other-salt")  # salt changes it
    assert a.startswith("host-")
    assert "203.0.113.44" not in a                        # address not embedded


def test_host_token_requires_salt():
    with pytest.raises(ValueError):
        host_token("203.0.113.44", "")


# ---- disclosure policy ----------------------------------------------------

def test_data_file_names_are_never_emitted():
    """A data file's NAME can be PII -> only its TYPE may appear."""
    records = [_rec("http://203.0.113.9/", "sensitive_exposure",
                    [_f("payroll_jane_doe_ssn.xlsx", 4200),
                     _f("acme_prod_backup.sql", 2_100_000_000)])]
    rows, _ = host_file_inventory(records, SALT)
    blob = repr(rows)
    for leaked in ("payroll_jane_doe_ssn", "acme_prod_backup", "203.0.113.9"):
        assert leaked not in blob
    # ...but the types are shown
    assert ".xlsx" in blob and ".sql" in blob
    for f in rows[0]["files"]:
        assert f["kind"] == "data" and "name" not in f


def test_exec_files_keep_their_name_and_get_hashes():
    """Executable/script names are PII-safe evidence: real name + hashes shown."""
    records = [_rec("http://203.0.113.9/", "malicious_staging",
                    [_f("webshell.php", 14000), _f("utils.sh", 2917)])]
    hashes = {("203.0.113.9", "utils.sh"): {"sha256": "463d97c1", "tlsh": "T1ABC", "vt": {"malicious": 0}}}
    rows, _ = host_file_inventory(records, SALT, hashes=hashes)
    files = {f.get("name"): f for f in rows[0]["files"] if f["kind"] == "exec"}
    assert "webshell.php" in files and "utils.sh" in files
    assert files["utils.sh"]["sha256"] == "463d97c1"
    assert files["utils.sh"]["tlsh"] == "T1ABC"
    assert "sha256" not in files["webshell.php"]           # no hash for it -> field absent


def test_alarm_only_on_webshells_and_vt_malicious_not_benign_exes():
    """A .exe is NOT inherently dangerous: the danger flag is reserved for
    webshell-named files and VirusTotal-flagged hashes."""
    records = [_rec("http://203.0.113.9/", "malicious_staging",
                    [_f("PyCharm-2025.exe", 10**9), _f("Xshell-8.0.exe", 500),
                     _f("backdoor.php", 500),
                     _f("clean_tool.sh", 100), _f("bad_tool.sh", 100)])]
    hashes = {
        ("203.0.113.9", "clean_tool.sh"): {"sha256": "aa", "vt": {"found": True, "malicious": 0}},
        ("203.0.113.9", "bad_tool.sh"): {"sha256": "bb", "vt": {"found": True, "malicious": 7}},
    }
    rows, _ = host_file_inventory(records, SALT, hashes=hashes)
    by = {f.get("name"): f for f in rows[0]["files"] if f["kind"] == "exec"}
    assert by["PyCharm-2025.exe"]["alarm"] is False        # benign installer
    assert by["Xshell-8.0.exe"]["alarm"] is False          # 'shell' substring, but a .exe not a web script
    assert by["clean_tool.sh"]["alarm"] is False           # VT clean
    assert by["backdoor.php"]["alarm"] is True             # web script + webshell name
    assert by["bad_tool.sh"]["alarm"] is True              # VT malicious


def test_output_contains_no_address_or_path():
    """Safety invariant: no hostname/IP/port/path may appear anywhere."""
    records = [_rec("https://targethost.zzqdomain:8443/leakzone/", "sensitive_exposure",
                    [_f("uniquefilename_secret.env", 400)])]
    rows, _ = host_file_inventory(records, SALT)
    blob = repr(rows)
    for leaked in ("targethost", "zzqdomain", "8443", "leakzone", "uniquefilename_secret"):
        assert leaked not in blob


# ---- aggregation / ranking ------------------------------------------------

def test_has_meta_flag_distinguishes_names_only_listings():
    """A server that publishes no sizes/dates (bare <ul> listing) -> has_meta False,
    so a blank size/date column can be labelled honestly rather than looking like a bug."""
    names_only = [_rec("http://a.example/", "sensitive_exposure",
                       [_f("app.zip"), _f("db.sql")])]              # no size/mtime
    with_meta = [_rec("http://b.example/", "sensitive_exposure",
                      [_f("app.zip", 1234, "2024-01-01T10:00")])]
    assert host_file_inventory(names_only, SALT)[0][0]["has_meta"] is False
    assert host_file_inventory(with_meta, SALT)[0][0]["has_meta"] is True


def test_inventory_flags_honeypot_via_port_fanout():
    """A byte-identical listing served across many ports of one host is flagged."""
    records = [
        {"url": f"http://h.example:{p}/", "label": "sensitive_exposure",
         "features": {}, "entries": [_f("passwords.zip", 1)], "raw_html_sha256": "SAMEHASH"}
        for p in (50100, 17001, 10342, 8080)
    ]
    rows, _ = host_file_inventory(records, SALT)
    assert rows[0]["honeypot"] and any("fan-out" in r for r in rows[0]["honeypot"]["reasons"])


def test_inventory_does_not_flag_ordinary_host():
    rows, _ = host_file_inventory(
        [{"url": "http://a.example/", "label": "sensitive_exposure",
          "features": {"sensitive_hits": {"env": 1}}, "entries": [_f("db.sql", 1)],
          "raw_html_sha256": "H"}], SALT)
    assert rows[0]["honeypot"] is None


def test_host_card_carries_signal_summary():
    """Each host card includes the semantic signal summary (folded in from the
    old per-host breakdown), derived from classifier signals + name mining."""
    rec = {"url": "http://a.example/", "label": "sensitive_exposure",
           "features": {"sensitive_hits": {"env": 1, "ssh_key": 1}, "payload_hits": {}},
           "entries": [_f("db.sql", 1), _f("customers.csv", 1)]}
    rows, _ = host_file_inventory([rec], SALT)
    sigs = rows[0]["signals"]
    assert ".env secrets" in sigs and "SSH keys" in sigs      # from features
    assert "personal-records files" in sigs                    # from name mining (customers.csv)


def test_ports_of_one_host_collapse():
    records = [_rec(f"http://h.example:{p}/", "sensitive_exposure", [_f("a.sql", 1)])
               for p in (8080, 8081, 9000)]
    rows, total = host_file_inventory(records, SALT)
    assert total == 1
    assert rows[0]["total"] == 3                            # three files merged under one token


def test_flagged_only_excludes_benign():
    records = [
        _rec("http://a.example/", "benign_index", [_f("readme.txt", 10)]),
        _rec("http://b.example/", "sensitive_exposure", [_f("db.sql", 10)]),
    ]
    rows, total = host_file_inventory(records, SALT)
    assert total == 1 and rows[0]["verdict"] == "sensitive"


def test_disclose_mode_includes_data_file_names():
    """Operator-chosen full disclosure: data-file names ARE included (opt-in)."""
    records = [_rec("http://203.0.113.9/", "sensitive_exposure",
                    [_f("clientes_export.sql", 4200), _f("backup.zip", 88)])]
    rows, _ = host_file_inventory(records, SALT, disclose=True)
    names = {f.get("name") for f in rows[0]["files"]}
    assert "clientes_export.sql" in names and "backup.zip" in names
    # ...but the host address is STILL never emitted, even under disclosure
    assert "203.0.113.9" not in repr(rows)


def test_disclose_off_by_default_withholds_data_names():
    records = [_rec("http://203.0.113.9/", "sensitive_exposure", [_f("clientes_export.sql", 1)])]
    rows, _ = host_file_inventory(records, SALT)                 # default
    assert "clientes_export" not in repr(rows)
    assert all("name" not in f for f in rows[0]["files"] if f["kind"] == "data")


def test_max_files_none_lists_every_file():
    entries = [_f(f"file{i}.dat", i) for i in range(30)]
    records = [_rec("http://a.example/", "sensitive_exposure", entries)]
    rows, _ = host_file_inventory(records, SALT, max_files=None)
    assert rows[0]["shown"] == 30 and rows[0]["hidden"] == 0


def test_caps_and_reports_hidden_count():
    entries = [_f(f"file{i}.dat", i) for i in range(30)]
    records = [_rec("http://a.example/", "sensitive_exposure", entries)]
    rows, _ = host_file_inventory(records, SALT, max_files=12)
    r = rows[0]
    assert r["shown"] == 12 and r["total"] == 30 and r["hidden"] == 18


def test_notable_ranking_alarm_then_sensitive_then_exec_then_large():
    entries = [
        _f("ordinary.dat", 5),
        _f("huge.iso", 500 * 1024 * 1024),   # large
        _f("installer.exe", 1000),           # plain executable (no alarm)
        _f("secrets.env", 20),               # sensitive-name data file
        _f("shell.php", 100),                # web-script webshell -> alarm
    ]
    records = [_rec("http://a.example/", "sensitive_exposure", entries)]
    rows, _ = host_file_inventory(records, SALT, max_files=5)
    files = rows[0]["files"]
    assert files[0]["kind"] == "exec" and files[0]["name"] == "shell.php"  # alarm first
    assert files[1]["ext"] == ".env"                       # sensitive data next
    assert files[2]["name"] == "installer.exe"             # plain executable next
    assert files[3]["ext"] == ".iso"                       # large data next
    assert files[4]["ext"] == ".dat"                       # ordinary last


def test_malicious_hosts_rank_before_sensitive():
    records = [
        _rec("http://s.example/", "sensitive_exposure", [_f("a.sql", 1)]),
        _rec("http://m.example/", "malicious_staging", [_f("shell.php", 1)]),
    ]
    rows, _ = host_file_inventory(records, SALT)
    assert rows[0]["verdict"] == "malicious"
