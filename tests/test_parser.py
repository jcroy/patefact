from pathlib import Path
import pytest
from opendir.capture.parser import parse_autoindex

FIX = Path(__file__).parent / "fixtures"

def _load(name):
    return (FIX / name).read_text()

@pytest.mark.parametrize("fixture,kind", [
    ("apache_index.html", "apache"),
    ("nginx_index.html", "nginx"),
    ("python_index.html", "python"),
])
def test_detects_server_kind(fixture, kind):
    res = parse_autoindex(_load(fixture), "http://ex.com/files/")
    assert res.server_kind == kind

@pytest.mark.parametrize("fixture", ["apache_index.html", "nginx_index.html", "python_index.html"])
def test_extracts_entries_without_parent(fixture):
    res = parse_autoindex(_load(fixture), "http://ex.com/files/")
    names = {e.name for e in res.entries}
    assert names == {"sub/", "data.zip"}
    assert not any("Parent" in e.name or e.name in ("../", "..") for e in res.entries)

@pytest.mark.parametrize("fixture", ["apache_index.html", "nginx_index.html", "python_index.html"])
def test_marks_directories(fixture):
    res = parse_autoindex(_load(fixture), "http://ex.com/files/")
    by_name = {e.name: e for e in res.entries}
    assert by_name["sub/"].is_dir is True
    assert by_name["data.zip"].is_dir is False
    assert by_name["data.zip"].path == "/files/data.zip"


def test_pre_apache_classified_as_apache():
    res = parse_autoindex(_load("apache_pre_index.html"), "http://ex.com/files/")
    assert res.server_kind == "apache"


def test_pre_apache_excludes_sort_and_parent_links():
    res = parse_autoindex(_load("apache_pre_index.html"), "http://ex.com/files/")
    names = {e.name for e in res.entries}
    assert names == {"sub/", "data.zip"}


def test_nginx_listing_of_icons_dir_is_nginx():
    res = parse_autoindex(_load("nginx_icons_dir.html"), "http://ex.com/static/icons/")
    assert res.server_kind == "nginx"


@pytest.mark.parametrize("fixture,prefix", [
    ("apache_index.html", "Index of"),
    ("nginx_index.html", "Index of"),
    ("python_index.html", "Directory listing for"),
])
def test_real_listings_are_recognized_as_open_dir(fixture, prefix):
    res = parse_autoindex(_load(fixture), "http://ex.com/files/")
    assert res.is_open_dir is True
    assert res.title.startswith(prefix)


def test_normal_website_is_not_an_open_dir():
    res = parse_autoindex(_load("not_a_listing.html"), "http://ex.com/")
    assert res.title == "Uno Pizzeria"
    assert res.is_open_dir is False
    # entries are still extracted even though this isn't a real listing
    names = {e.name for e in res.entries}
    assert names == {"Menu", "Jobs"}


# ---- size + mtime extraction (all three metadata-bearing formats agree) ----

@pytest.mark.parametrize("fixture", ["apache_index.html", "nginx_index.html", "apache_pre_index.html"])
def test_extracts_size_and_mtime(fixture):
    res = parse_autoindex(_load(fixture), "http://ex.com/files/")
    by = {e.name: e for e in res.entries}
    # data.zip is 2.5K (Apache) == 2560 bytes (nginx); dated 2024-01-03 11:30
    assert by["data.zip"].size == 2560
    assert by["data.zip"].mtime == "2024-01-03T11:30"
    # a directory shows "-" for size -> None, but still has an mtime
    assert by["sub/"].size is None
    assert by["sub/"].mtime == "2024-01-02T10:00"


def test_python_listing_has_no_size_or_mtime():
    res = parse_autoindex(_load("python_index.html"), "http://ex.com/files/")
    for e in res.entries:
        assert e.size is None
        assert e.mtime is None


@pytest.mark.parametrize("text,expected", [
    ("2560", 2560), ("2.5K", 2560), ("4.0M", 4194304),
    ("1G", 1073741824), ("-", None), ("", None), ("bogus", None),
])
def test_parse_size_units(text, expected):
    from opendir.capture.parser import _parse_size
    assert _parse_size(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("03-Jan-2024 11:30", "2024-01-03T11:30"),   # nginx form
    ("2024-01-03 11:30", "2024-01-03T11:30"),    # apache iso form
    ("-", None), ("", None),
])
def test_parse_mtime_forms(text, expected):
    from opendir.capture.parser import _parse_mtime
    assert _parse_mtime(text) == expected
