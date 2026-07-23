from opendir.classify.features import extract_features
from opendir.classify.rules import classify, RULESET_VERSION


def feats(*names):
    return extract_features([{"name": n, "is_dir": False} for n in names])


def test_malicious_from_webshell():
    r = classify(feats("reverse_shell.php", "db.sql"))
    assert r["label"] == "malicious_staging" and r["confidence"] >= 0.6
    assert r["ruleset_version"] == RULESET_VERSION


def test_sensitive_from_env_git_sql():
    r = classify(feats(".env", ".git", "backup.sql", "wp-config.php"))
    assert r["label"] == "sensitive_exposure" and r["confidence"] > 0.6


def test_intentional_from_mirror():
    r = classify(feats("a.zip", "b.iso", "c.tar", "d.deb"))
    assert r["label"] == "intentional_public"


def test_benign_default():
    r = classify(feats("readme.txt", "notes.md", "image.png"))
    assert r["label"] == "benign_index"


def test_executables_flagged_sensitive():
    r = classify(feats("setup.exe", "run.bat"))  # payload but no webshell/mirror
    assert r["label"] == "sensitive_exposure"
