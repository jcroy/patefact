"""Tests for the potential-honeypot identifier (opendir.analyze.honeypot)."""
from opendir.analyze.honeypot import bait_categories, assess


def _f(name):
    return {"name": name, "is_dir": False}


# the exact bait shape observed in the wild (a real honeypot lure host)
BAIT_LISTING = [
    _f("wp_backup_20251015.zip"), _f("site-backup.zip"), _f("database-backup.zip"),
    _f("backup_db.sql.gz"), _f("dump.sql.gz"), _f("config.zip"),
    _f("passwords.zip"), _f("ssh_keys.tar.gz"), _f(".env"), _f("robots.txt"),
]


def test_bait_cluster_flags_the_lure():
    cats = bait_categories(BAIT_LISTING)
    assert {"passwords", "ssh_keys", "db_dump", "env"} <= cats
    is_hp, score, reasons = assess(BAIT_LISTING)
    assert is_hp is True
    assert any("curated bait" in r for r in reasons)


def test_port_fanout_flags_identical_listing_across_ports():
    # even a modest listing served byte-identically on many ports is a trap
    is_hp, score, reasons = assess([_f("readme.txt"), _f("index.html")],
                                   port_fanout=6, identical_fanout=4)
    assert is_hp is True
    assert any("scanner fan-out" in r for r in reasons)


def test_ordinary_leak_is_not_flagged():
    # a real single-app leak: a couple sensitive files, one port -> not a honeypot
    entries = [_f(".env"), _f("backup.sql"), _f("index.php"), _f("composer.json")]
    is_hp, score, reasons = assess(entries, port_fanout=1, identical_fanout=1)
    assert is_hp is False
    assert reasons == []


def test_empty_listing_is_not_flagged():
    is_hp, score, reasons = assess([], port_fanout=1, identical_fanout=1)
    assert is_hp is False
