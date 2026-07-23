"""Heuristic "potential honeypot" identifier for open directories.

Some "open directories" are bait: hand-crafted lures with a suspiciously curated
set of high-value files (``passwords.zip`` + ``ssh_keys.tar.gz`` + database dumps
+ ``.env``) -- often fanned across many ports -- designed to trap scanners and
bait credential-harvesters. This flags them from data we already hold (filenames
+ the raw-HTML fingerprint across ports), so a lure isn't mistaken for a real
leak. Address-free; no re-capture needed.

Two signals:
  1. curated bait cluster -- several DISTINCT high-value bait categories present
     in one listing (a real breach rarely exposes every juicy type at once);
  2. port fan-out -- a byte-identical listing served across multiple ports of a
     single host (same raw_html_sha256), the classic scanner-trap shape.

Not definitive: page-level tells (auto-download <iframe>/<script>, fake creds in
HTML comments) are stronger but need the raw body, which capture discards -- so
they are a documented follow-up (add extraction to run_capture, then re-capture).
"""
import re

# "Too perfect" bait -- the exact files an attacker hopes to find, curated together.
BAIT_PATTERNS = {
    "passwords":    r"password",
    "ssh_keys":     r"ssh[_-]?key|id_rsa|id_ed25519|authorized_keys",
    "db_dump":      r"(database|db|mysql|prod|dump)[-_ ]?(backup|dump|export)?\.(sql|gz|zip)|dump\.sql",
    "env":          r"(^|/|\b)\.env(\b|$)",
    "wallet":       r"wallet\.dat|private[_-]?key|\.pem$",
    "credentials":  r"credential|(^|[-_./])secret|\.aws|api[_-]?key",
    "config_arch":  r"config\.(zip|tar|gz|rar|7z)",
    "backup_arch":  r"backup.*\.(zip|tar|gz|rar|7z)",
}
_BAIT = {k: re.compile(v, re.I) for k, v in BAIT_PATTERNS.items()}

_MIN_BAIT = 4        # distinct bait categories to call a listing "curated"
_MIN_FANOUT = 3      # identical listings across this many ports -> scanner trap


def bait_categories(entries):
    """Distinct high-value bait categories whose names appear in the listing."""
    found = set()
    for e in entries or []:
        name = str(e.get("name", "")).lower()
        for cat, rx in _BAIT.items():
            if rx.search(name):
                found.add(cat)
    return found


def assess(entries, *, port_fanout=1, identical_fanout=1):
    """Return ``(is_potential_honeypot, score, reasons)`` for one host.

    ``port_fanout``: distinct ports this host serves. ``identical_fanout``:
    ports serving a BYTE-IDENTICAL listing (max raw_html_sha256 group size).
    """
    reasons = []
    bait = bait_categories(entries)
    if len(bait) >= _MIN_BAIT:
        reasons.append(f"curated bait — {len(bait)} high-value file types "
                       f"({', '.join(sorted(bait))})")
    if identical_fanout >= _MIN_FANOUT:
        reasons.append(f"identical listing on {identical_fanout} ports (scanner fan-out)")
    is_hp = len(bait) >= _MIN_BAIT or identical_fanout >= _MIN_FANOUT
    score = len(bait) + (3 if identical_fanout >= _MIN_FANOUT else 0)
    return is_hp, score, reasons
