from opendir.payload.select import select_payload_urls


def _e(name, is_dir=False, href=None):
    return {"name": name, "is_dir": is_dir, "href": href or name}


def test_selects_only_allowlisted_types():
    entries = [_e("mal.exe"), _e("run.ps1"), _e("data.sql"), _e("photo.jpg"),
               _e("archive.zip"), _e("readme.txt"), _e("sub/", is_dir=True), _e("lib.dll")]
    urls = select_payload_urls(entries, "http://h/")
    names = {u["name"] for u in urls}
    assert names == {"mal.exe", "run.ps1", "lib.dll"}   # sql/jpg/zip/txt/dir excluded


def test_selects_webshell_named_scripts():
    urls = select_payload_urls([_e("index.php"), _e("shell.php"), _e("c99.php")], "http://h/")
    assert {u["name"] for u in urls} == {"shell.php", "c99.php"}   # plain index.php excluded


def test_builds_absolute_urls_and_caps():
    urls = select_payload_urls([_e(f"f{i}.exe") for i in range(60)], "http://h/d/", max_files=10)
    assert len(urls) == 10 and urls[0]["url"] == "http://h/d/f0.exe"
