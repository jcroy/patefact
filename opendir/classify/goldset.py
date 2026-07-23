"""Behavioral gold set for the open-directory classifier.

Each case is a small, realistic ``listing_entries`` shape paired with the
label the classifier is *intended* to produce, plus a note explaining why.
These are ground-truth-by-construction: they encode the intended semantics
of feature extraction + the ruleset, so they double as a regression suite
(``tests/test_classify_goldset.py``) and as the data behind the human-facing
accuracy report (``scripts/eval_classifier.py``).

They deliberately include the non-obvious edges a future ruleset edit could
silently regress:
  * a bare ``backup/`` dir is a *non-trigger* (only ``sql_dump`` catches
    ``backup.sql``), so it stays benign;
  * a mirror needs >= 3 files -- one stray ``.zip`` is not "intentional";
  * sensitive/payload patterns match *directory* names too (exposed
    ``.git/`` fires even though it is a dir entry);
  * severity ordering: a dir with both a webshell and a ``.env`` is
    malicious_staging, not sensitive_exposure.

A case's ``entries`` use the same dict shape as ``Snapshot.listing_entries``
(only ``name`` and ``is_dir`` affect classification).
"""


def _f(name):
    return {"name": name, "is_dir": False}


def _d(name):
    return {"name": name, "is_dir": True}


# id, entries, server_kind, expected label, note
GOLD_CASES = [
    # --- sensitive_exposure: strong trigger categories ---
    ("env-file", [_f(".env"), _f("index.php")], "apache", "sensitive_exposure",
     "exposed .env -> application secrets leak"),
    ("git-dir", [_d(".git"), _f("index.html")], "nginx", "sensitive_exposure",
     "exposed .git/ directory -> full source + history (pattern matches dir names)"),
    ("ssh-key", [_f("id_rsa"), _f("id_rsa.pub"), _f("authorized_keys")], "apache",
     "sensitive_exposure", "private SSH key material"),
    ("sql-dump", [_f("backup.sql"), _f("readme.txt")], "nginx", "sensitive_exposure",
     "database dump (backup.sql matches sql_dump, not the non-trigger 'backup')"),
    ("wp-config", [_f("wp-config.php"), _f("index.php")], "apache", "sensitive_exposure",
     "wp-config.php -> DB credentials"),
    ("priv-key-pem", [_f("server.pem"), _f("cert.crt")], "nginx", "sensitive_exposure",
     "private key .pem"),
    ("sqlite-db", [_f("app.sqlite3"), _f("app.py")], "python", "sensitive_exposure",
     "shipped SQLite database file"),
    ("htpasswd", [_f(".htpasswd"), _f(".htaccess")], "apache", "sensitive_exposure",
     ".htpasswd (config trigger) -> hashed creds"),

    # --- malicious_staging: webshell / offensive tooling ---
    ("webshell-c99", [_f("c99.php"), _f("index.php")], "apache", "malicious_staging",
     "c99 webshell present"),
    ("webshell-shell-php", [_f("shell.php"), _f("index.php")], "apache", "malicious_staging",
     "a web-script named shell.php is a webshell (still caught after the ext tightening)"),
    ("malware-mimikatz", [_f("mimikatz.exe"), _f("readme.txt")], "iis", "malicious_staging",
     "mimikatz (malware_tool) staged"),
    ("malicious-over-sensitive", [_f("c99.php"), _f(".env"), _f("dump.sql")], "apache",
     "malicious_staging", "severity ordering: webshell wins over sensitive signals"),

    # --- sensitive_exposure (weak): payload present, no clear webshell ---
    ("lone-exe", [_f("setup.exe"), _f("readme.txt")], "iis", "sensitive_exposure",
     "executable without mirror/webshell context -> weak sensitive"),
    ("lone-ps1", [_f("deploy.ps1"), _f("notes.md")], "iis", "sensitive_exposure",
     "PowerShell script -> weak sensitive"),

    # --- intentional_public: archive/media/installer mirror, >= 3 files ---
    ("archive-mirror", [_f("v1.zip"), _f("v2.tar"), _f("v3.iso"), _f("v4.gz")], "nginx",
     "intentional_public", "predominantly archive files, mirror-like"),
    ("media-mirror", [_f("ep1.mp4"), _f("ep2.mkv"), _f("ep3.mp4")], "nginx",
     "intentional_public", "predominantly media files, mirror-like"),
    ("software-installer-mirror",
     [_f("PyCharm-2025.2.exe"), _f("GoogleChrome.exe"), _f("Xshell-8.0.exe"), _f("Wireshark-4.6.exe")],
     "nginx", "intentional_public",
     "a software-installer mirror: executables are mirror content and there is no "
     "webshell/tool/secret, so it is intentional_public -- NOT malicious ('Xshell' "
     "must not read as a webshell, and .exe presence alone must not escalate)"),

    # --- benign_index: no notable signal, or below thresholds ---
    ("bare-backup-dir", [_d("backup"), _f("index.html")], "apache", "benign_index",
     "bare 'backup' is a NON-trigger category -> stays benign (documents the quirk)"),
    ("single-zip", [_f("release.zip"), _d("docs")], "nginx", "benign_index",
     "one archive is below the >=3-file mirror threshold -> benign, not intentional"),
    ("plain-index", [_f("readme.txt"), _f("index.html"), _d("images")], "apache",
     "benign_index", "ordinary listing, no sensitive/payload/mirror signal"),
    ("empty-ish", [_d("Parent Directory")], "apache", "benign_index",
     "effectively empty listing"),
]
