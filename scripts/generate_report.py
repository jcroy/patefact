#!/usr/bin/env python
"""Generate an aggregate demo report from the patefact corpus.

Read-only. Produces Markdown to stdout (redirect to docs/DEMO_REPORT.md).
All output is AGGREGATE: individual host addresses/orgs are withheld because
these are live, real-world exposures — a public report must not point at victims.

    uv run python scripts/generate_report.py > docs/DEMO_REPORT.md
"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django  # noqa: E402

django.setup()

from django.utils import timezone  # noqa: E402
from opendir.models import Candidate, Snapshot, Classification, PayloadHash  # noqa: E402
from opendir.classify.features import EXTRACTOR_VERSION  # noqa: E402
from opendir.classify.rules import RULESET_VERSION  # noqa: E402
from opendir.analyze.inventory import scan_names, size_stats  # noqa: E402
from opendir.analyze.file_listing import host_file_inventory  # noqa: E402
from opendir.analyze.ownership import profile_breakdown, CATEGORY_DISPLAY, CATEGORY_ORDER  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402

INTEREST_LABELS = {
    "personal_records": "personal records (customers/employees/passwords)",
    "financial": "financial data (invoices/bank/payroll)",
    "cloud_creds": "cloud credentials (aws/kube/tfstate)",
    "auth_secrets": "auth secrets / tokens / keystores",
    "vcs_source": "VCS / source-control dirs",
    "logs": "log files",
}


def _human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


SENSITIVE_LABELS = {
    "env": ".env files", "git": "exposed .git repos", "sql_dump": "SQL dumps",
    "backup": "backups", "ssh_key": "SSH keys", "priv_key": "private keys",
    "config": "config files", "credential": "credential files",
    "database": "database files", "capture": "packet captures", "vpn": "VPN configs",
}
PAYLOAD_LABELS = {
    "webshell": "webshells/backdoors", "executable": "executables (.exe/.dll)",
    "script": "scripts (.ps1/.bat/.sh)", "malware_tool": "known offensive tools",
    "binary": "raw binaries",
}


def _pct(n, total):
    return f"{100 * n / total:.0f}%" if total else "0%"


def _latest_open_dir_snaps():
    latest = {}
    for s in Snapshot.objects.filter(is_open_dir=True).order_by("fetched_at"):
        latest[s.candidate_id] = s
    return list(latest.values())


def main():
    full_names = "--full-names" in sys.argv   # operator opt-in: unredacted data-file names
    out = []
    w = out.append

    n_candidates = Candidate.objects.count()
    n_captured = Candidate.objects.filter(status="captured").count()
    open_dirs = _latest_open_dir_snaps()
    n_open = len(open_dirs)
    # non-listing captures (matched "Index of /" on Shodan but weren't actually a listing)
    n_not_listing = (
        Snapshot.objects.filter(http_status=200, is_open_dir=False)
        .values("candidate").distinct().count()
    )
    validated_total = n_open + n_not_listing

    w("# patefact — Demo Report\n")
    w(f"_Generated {timezone.now():%Y-%m-%d}. Aggregate figures only — individual host "
      "addresses and operators are withheld, since these are live real-world exposures._\n")

    w("## Pipeline\n")
    w("Shodan discovery → capture via a **disposable, self-destructing cloud worker** "
      "(a DigitalOcean droplet; requests never originate from the operator's IP) → "
      "autoindex validation → deterministic rules-first classification. Untrusted HTML "
      "is parsed and fingerprinted **on the disposable worker**; only structured, "
      "derived data returns.\n")

    w("## Corpus\n")
    w(f"- **Candidates discovered** (Shodan): {n_candidates}")
    w(f"- **Captured**: {n_captured}")
    w(f"- **Validated open directories**: {n_open}")
    if validated_total:
        w(f"- **False-positive rate**: {_pct(n_not_listing, validated_total)} of pages that "
          f"matched Shodan's `Index of /` title were actually normal websites (stale matches) "
          f"— caught and excluded by title/`<h1>` validation.\n")
    else:
        w("")

    # Network profile: where the exposed hosts live, by ASN owner (Shodan org).
    seen_ip, orgs, countries = set(), [], Counter()
    for s in open_dirs:
        m = s.candidate.source_meta or {}
        ip = m.get("ip") or urlsplit(s.candidate.url).hostname
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        orgs.append(m.get("org"))
        countries[m.get("country") or "?"] += 1
    cat_counts, prov_counts = profile_breakdown(orgs)
    n_net = sum(cat_counts.values())
    if n_net:
        w("## Network profile\n")
        w("Where the exposed hosts actually live, by their ASN owner (from Shodan — no extra "
          "lookups). Open directories cluster on **cloud & hosting infrastructure**, not home "
          "connections:\n")
        w("| Network type | Hosts | Share |")
        w("|---|---:|---:|")
        for c in CATEGORY_ORDER:
            if cat_counts.get(c):
                w(f"| {CATEGORY_DISPLAY[c]} | {cat_counts[c]} | {_pct(cat_counts[c], n_net)} |")
        w("")
        w("**Top providers**: " + ", ".join(f"{p} ({n})" for p, n in prov_counts.most_common(8)))
        w("\n**Top countries**: " + ", ".join(f"{c} ({n})" for c, n in countries.most_common(10)) + "\n")

    # Classification distribution (current ruleset), counted over the LATEST
    # snapshot per open directory -- not every Classification row, since a
    # re-captured host has several snapshots and would otherwise be counted once
    # per snapshot (inflating the totals).
    labels = Counter()
    for s in open_dirs:
        cls = (s.classifications.filter(ruleset_version=RULESET_VERSION)
               .order_by("-classified_at").first())
        if cls:
            labels[cls.label] += 1
    n_classified = sum(labels.values())
    w("## Classification\n")
    if n_classified:
        w(f"Rules-first classifier (ruleset `v{RULESET_VERSION}`), {n_classified} dirs:\n")
        w("| Label | Count | Share |")
        w("|---|---:|---:|")
        for label in ["malicious_staging", "sensitive_exposure",
                      "intentional_public", "benign_index", "unknown"]:
            if labels.get(label):
                w(f"| `{label}` | {labels[label]} | {_pct(labels[label], n_classified)} |")
        w("")
    else:
        w("_(no classifications yet — run `manage.py classify`)_\n")

    # Signal prevalence across validated open dirs
    sens_dirs = Counter()
    pay_dirs = Counter()
    ext_dirs = Counter()  # number of directories containing each extension (dir-prevalence)
    server_kinds = Counter()
    interest_dirs = Counter()   # name-based inventory mining (dir-prevalence)
    sized_dirs = total_exposed_bytes = big_files = 0
    for s in open_dirs:
        server_kinds[s.server_kind] += 1
        entries = s.listing_entries or []
        for cat in scan_names(entries):
            interest_dirs[cat] += 1
        st = size_stats(entries)
        if st["has_sizes"]:
            sized_dirs += 1
            total_exposed_bytes += st["total_bytes"]
            big_files += st["files_over_100mb"]
        cls = s.classifications.order_by("-classified_at").first()
        feats = cls.features if cls else None
        if not feats:
            continue
        for cat, n in feats.get("sensitive_hits", {}).items():
            if n:
                sens_dirs[cat] += 1
        for cat, n in feats.get("payload_hits", {}).items():
            if n:
                pay_dirs[cat] += 1
        for ext in feats.get("top_exts", {}):
            ext_dirs[ext] += 1

    w("## What was exposed (aggregate signal prevalence)\n")
    w("Number of open directories in which each signal appeared:\n")
    if sens_dirs or pay_dirs:
        w("| Signal | Dirs |")
        w("|---|---:|")
        for cat, n in sens_dirs.most_common():
            w(f"| {SENSITIVE_LABELS.get(cat, cat)} | {n} |")
        for cat, n in pay_dirs.most_common():
            w(f"| ⚠️ {PAYLOAD_LABELS.get(cat, cat)} | {n} |")
        w("")
    else:
        w("_(none detected yet)_\n")

    w("## File types\n")
    if ext_dirs:
        w("Most common file extensions, by number of directories containing them:\n")
        w("| Ext | Dirs |")
        w("|---|---:|")
        for ext, n in ext_dirs.most_common(12):
            w(f"| `{ext}` | {n} |")
        w("")
    w("## Server software\n")
    if server_kinds:
        w(", ".join(f"{k}: {v}" for k, v in server_kinds.most_common()) + "\n")

    # Deeper inventory mining: name-based characterization beyond the classifier's
    # verdict signals. Counts only -- individual filenames can themselves be PII.
    w("## Deeper inventory mining (name-based)\n")
    w("Heuristic characterization from **filenames only** — no content is ever "
      "accessed, so a match means the *name suggests* that content. Number of open "
      "directories containing at least one match:\n")
    if interest_dirs:
        w("| Category | Dirs |")
        w("|---|---:|")
        for cat, n in interest_dirs.most_common():
            w(f"| {INTEREST_LABELS.get(cat, cat)} | {n} |")
        w("")
    else:
        w("_(none detected)_\n")
    if sized_dirs:
        w(f"- **Exposed volume**: {sized_dirs} dirs report file sizes — "
          f"~{_human_bytes(total_exposed_bytes)} of listed files, "
          f"{big_files} single files over 100 MB.\n")

    # Per-host records (origin host, ports collapsed): the file inventory below
    # renders one anonymized card per host with its signal summary + files.
    records = [
        {"url": s.candidate.url,
         "label": (cls := s.classifications.order_by("-classified_at").first()) and cls.label,
         "features": cls.features if cls else {},
         "entries": s.listing_entries or [],
         "raw_html_sha256": s.raw_html_sha256}
        for s in open_dirs
        if s.classifications.exists()
    ]

    # Per-host FILE inventory (anonymized). Disclosure policy lives in
    # opendir.analyze.file_listing: IOC files (executables/scripts/webshells)
    # are shown by name + hash; all other files show TYPE + size + date only,
    # because a data filename can itself be PII. Host tokens are salted HMACs.
    salt = os.environ.get("REPORT_HOST_SALT", "")
    if salt:
        hashes = {}
        for p in PayloadHash.objects.exclude(sha256=""):
            host = urlsplit(p.url).hostname or ""
            hashes[(host, p.name)] = {"sha256": p.sha256, "tlsh": p.tlsh, "vt": p.vt}
        finv, n_hosts = host_file_inventory(
            records, salt, hashes=hashes,
            max_files=None if full_names else 10, disclose=full_names)
        n_hp = sum(1 for r in finv if r.get("honeypot"))

        def _fsize(b):
            return _human_bytes(b) if isinstance(b, int) else "—"

        def _hash_cell(f):
            if f["kind"] != "exec" or not f.get("sha256"):
                return "—"
            cell = f"`sha256:{f['sha256'][:12]}…`"
            vt = f.get("vt")
            if isinstance(vt, dict) and vt.get("found"):
                mal = vt.get("malicious", 0)
                cell += f" · VT: {mal} malicious" if mal else " · VT: clean"
            return cell

        def _flabel(f):
            if f["kind"] == "exec":
                return f"⚠ `{f['name']}`" if f.get("alarm") else f"`{f['name']}`"
            return f"`{f.get('name') or f['ext']}`"

        hlimit = n_hosts if full_names else 20
        if full_names:
            w("## Per-host file inventory (FULL — unredacted)\n")
            w("**Full-disclosure mode.** Every file is listed by its real name — data "
              "files included — for all flagged hosts. Host addresses are still withheld "
              "(salted-HMAC tokens), but **filenames can contain PII**, so treat this as "
              "sensitive and review before any public release.\n")
        else:
            w("## Per-host file inventory (anonymized)\n")
            w("Concrete file-level evidence per **pseudonymous host** — a salted-HMAC token, "
              "stable but non-reversible (a bare hash of an IP would be trivially reversible). "
              "**Executable and script files are shown by name** (a program name isn't PII), with "
              "content hashes where we hashed them; a **⚠ marks confirmed webshells or "
              "VirusTotal-flagged files**. **Every other file shows only its type, size, and date** "
              "— filenames are withheld because a data filename can itself be PII. "
              f"Worst {min(hlimit, n_hosts)} of {n_hosts} flagged hosts:\n")
        if n_hp:
            w(f"\n_**{n_hp}** of these hosts are flagged as **potential honeypots** — bait "
              "listings (a curated set of high-value files, or a byte-identical listing fanned "
              "across many ports) that mimic a leak to trap scanners. Marked ⚠ below._\n")
        for row in finv[:hlimit]:
            w(f"#### `{row['token']}` — {row['verdict']} — {row['total']} files")
            if row.get("honeypot"):
                w(f"> ⚠️ **Potential honeypot** — {'; '.join(row['honeypot']['reasons'])}\n")
            if row.get("signals"):
                w(f"_Signals: {' · '.join(row['signals'])}_\n")
            if not row.get("has_meta"):
                w("_Names-only listing — this server publishes no file sizes or dates._\n")
            w("| File | Size | Modified | Hash |")
            w("|---|---:|---|---|")
            for f in row["files"]:
                w(f"| {_flabel(f)} | {_fsize(f['size'])} | {f['mtime'] or '—'} | {_hash_cell(f)} |")
            if row["hidden"]:
                w(f"| _+{row['hidden']} more files_ | | | |")
            w("")
        if n_hosts > hlimit:
            w(f"_…and {n_hosts - hlimit} more flagged hosts (full inventory in the local DB "
              "only; addresses and data-file names are never published)._\n")

    # Payload analysis (Tier-2: hash-and-discard in Modal + VirusTotal lookup)
    hashed = PayloadHash.objects.exclude(sha256="").count()
    skipped = PayloadHash.objects.filter(sha256="").count()
    vt_found = PayloadHash.objects.filter(vt__found=True).count()
    vt_malicious = PayloadHash.objects.filter(vt__malicious__gt=0).count()
    pay_types = Counter(
        p.name.rsplit(".", 1)[-1].lower()
        for p in PayloadHash.objects.exclude(sha256="") if "." in p.name
    )
    if hashed or skipped:
        w("## Payload analysis\n")
        w("For directories flagged sensitive/malicious, an allowlist of **executable/script "
          "files only** (never media, archives, documents, or data files) is downloaded, hashed, "
          "and **discarded on the disposable worker** — only the hash is kept. Sensitive-data files "
          "(`.env`, `.sql`, …) are documented from the listing and **never downloaded**.\n")
        w(f"- **Payloads hashed** (SHA-256 + TLSH, hash-and-discard): {hashed}"
          + (f"  ·  {skipped} skipped (over size cap / unreachable)" if skipped else ""))
        if pay_types:
            w(f"- **Types hashed**: " + ", ".join(f"`.{e}`×{n}" for e, n in pay_types.most_common()))
        if PayloadHash.objects.filter(vt__isnull=False).exists():
            w(f"- **VirusTotal (lookup-by-hash, never submitted)**: {vt_found} known to VT, "
              f"**{vt_malicious} flagged malicious**")
            if vt_malicious == 0 and vt_found:
                w("  - The recognized payloads are legitimate software/config scripts, not "
                  "malware — consistent with the corpus being *exposures/misconfigurations* "
                  "rather than active malware staging.")
        w("")

    w("## Notable patterns\n")
    w("- **Targeted discovery works**: queries like `http.html:\".env\"` / `\".sql\"` "
      "surfaced directories with a far higher sensitive-content rate than a generic "
      "`Index of /` sweep (which is dominated by benign software/media mirrors).")
    w("- **Infrastructure clustering**: a single staging host was observed across ~12 "
      "different ports serving byte-identical SQL-dump listings — the kind of one-host, "
      "many-ports fan-out that graph-based infrastructure analysis (planned P3) surfaces.")
    w("- **Validation matters**: a meaningful fraction of Shodan `Index of /` matches were "
      "stale — the host now serves an ordinary website — and were correctly rejected before "
      "classification.\n")

    w("## Reproducibility\n")
    w(f"Deterministic throughout: feature extractor `v{EXTRACTOR_VERSION}`, ruleset "
      f"`v{RULESET_VERSION}`. Every classification stores its full feature vector plus both "
      "version stamps, so any verdict can be reproduced or re-run under a new ruleset.\n")

    print("\n".join(out))


if __name__ == "__main__":
    main()
