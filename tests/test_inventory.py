"""Tests for the name-based inventory characterization layer."""
import pytest

from opendir.analyze.inventory import scan_names, size_stats, analyze


def _cats(name, is_dir=False):
    return set(scan_names([{"name": name, "is_dir": is_dir}]).keys())


@pytest.mark.parametrize("name,expected", [
    ("customers.csv", {"personal_records"}),
    ("employees.xlsx", {"personal_records"}),
    ("patients.sql", {"personal_records"}),
    ("passwords.txt", {"personal_records"}),
    ("payroll.xlsx", {"personal_records", "financial"}),   # payroll spans both
    ("invoices.csv", {"financial"}),
    ("bank_statements.pdf", {"financial"}),
    ("wallet.dat", {"financial"}),
    ("credentials", {"cloud_creds"}),
    (".npmrc", {"cloud_creds"}),
    ("terraform.tfstate", {"cloud_creds"}),
    ("service-account.json", {"cloud_creds"}),
    ("api_key.txt", {"auth_secrets"}),
    ("keystore.p12", {"auth_secrets"}),
    ("secrets.yml", {"auth_secrets"}),
    ("access.log", {"logs"}),
    (".DS_Store", {"vcs_source"}),
])
def test_scan_names_positive(name, expected):
    assert _cats(name) >= expected


@pytest.mark.parametrize("name,is_dir", [
    ("users", True),        # a framework users/ dir has no data ext -> not PII
    ("clients", True),
    ("index.html", False),
    ("app.py", False),
    ("style.css", False),
    ("logo.png", False),
])
def test_scan_names_no_false_pii(name, is_dir):
    cats = _cats(name, is_dir)
    assert "personal_records" not in cats
    assert "financial" not in cats


def test_scan_names_counts_and_examples():
    entries = [{"name": f"customer_{i}.csv", "is_dir": False} for i in range(9)]
    result = scan_names(entries, max_examples=3)
    assert result["personal_records"]["count"] == 9
    assert len(result["personal_records"]["examples"]) == 3


def test_git_dir_is_vcs_source():
    assert "vcs_source" in _cats(".git", is_dir=True)


def test_size_stats_no_sizes():
    entries = [
        {"name": "a.zip", "is_dir": False, "size": None},
        {"name": "d", "is_dir": True, "size": None},
    ]
    st = size_stats(entries)
    assert st["has_sizes"] is False
    assert st["total_bytes"] == 0
    assert st["file_count"] == 1


def test_size_stats_with_sizes():
    entries = [
        {"name": "small.txt", "is_dir": False, "size": 100},
        {"name": "big.sql", "is_dir": False, "size": 200 * 1024 * 1024},
        {"name": "sub", "is_dir": True, "size": None},
    ]
    st = size_stats(entries)
    assert st["has_sizes"] is True
    assert st["total_bytes"] == 100 + 200 * 1024 * 1024
    assert st["largest_name"] == "big.sql"
    assert st["files_over_100mb"] == 1
    assert st["file_count"] == 2


def test_analyze_combines_both():
    result = analyze([{"name": "customers.csv", "is_dir": False, "size": 500}])
    assert "personal_records" in result["interest"]
    assert result["size"]["total_bytes"] == 500
