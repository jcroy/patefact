from opendir.classify.features import extract_features, EXTRACTOR_VERSION


def _e(*names, dirs=()):
    return [{"name": n, "is_dir": False} for n in names] + [{"name": d, "is_dir": True} for d in dirs]


def test_counts_files_and_dirs():
    f = extract_features(_e("a.zip", "b.txt", dirs=("sub/",)))
    assert f["file_count"] == 2 and f["dir_count"] == 1 and f["entry_count"] == 3


def test_sensitive_and_payload_hits():
    f = extract_features(_e(".env", "db_dump.sql", "id_rsa", "shell.php", "tool.exe"))
    assert f["sensitive_hits"]["env"] == 1
    assert f["sensitive_hits"]["sql_dump"] == 1
    assert f["sensitive_hits"]["ssh_key"] == 1
    assert f["payload_hits"]["webshell"] == 1
    assert f["payload_hits"]["executable"] == 1


def test_mirror_ratio_and_exts():
    f = extract_features(_e("a.zip", "b.zip", "c.iso", "readme.txt"))
    assert f["mirror_files"] == 3 and abs(f["mirror_ratio"] - 0.75) < 1e-6
    assert f["top_exts"][".zip"] == 2


def test_cert_self_signed_from_tls():
    assert extract_features(_e("a"), tls={"self_signed": True})["cert_self_signed"] is True
    assert extract_features(_e("a"))["cert_self_signed"] is False

def test_git_directory_is_detected():
    # .git normally appears as a DIRECTORY entry; exposed-repo detection must still fire
    f = extract_features([{"name": ".git", "is_dir": True},
                          {"name": "index.html", "is_dir": False}])
    assert f["sensitive_hits"]["git"] == 1
    assert f["dir_count"] == 1 and f["file_count"] == 1
