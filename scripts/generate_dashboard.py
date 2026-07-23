#!/usr/bin/env python
"""Generate a self-contained HTML dashboard from the patefact corpus.

Read-only. Writes one complete, dependency-free HTML document (inline CSS,
CSS-only readout bars, no web fonts or CDNs) to the given path or stdout.
Every figure is AGGREGATE: individual host addresses/operators are withheld --
these are live real-world exposures.

Aesthetic: a dark "forensic field report" -- editorial serif masthead over
monospace data. A capture pipeline strip and a 6-up KPI band sit under the
masthead; findings live in a 12-column panel deck; the per-host evidence is an
expandable table (click a row to open its file listing), paged.

    uv run python scripts/generate_dashboard.py            # -> stdout
    uv run python scripts/generate_dashboard.py dashboard.html
    uv run python scripts/generate_dashboard.py --full-names dashboard.full.html
"""
import html
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

_CAT_COLOR = {
    "cloud": "var(--blue)", "hosting": "var(--violet)", "residential": "var(--green)",
    "academic": "var(--rose)", "business": "var(--amber)", "unknown": "var(--steel)",
}

INTEREST_LABELS = {
    "personal_records": "personal records", "financial": "financial data",
    "cloud_creds": "cloud credentials", "auth_secrets": "auth secrets / tokens",
    "vcs_source": "VCS / source dirs", "logs": "log files",
}
SENSITIVE_LABELS = {
    "env": ".env files", "git": "exposed .git", "sql_dump": "SQL dumps",
    "backup": "backups", "ssh_key": "SSH keys", "priv_key": "private keys",
    "config": "config files", "credential": "credential files",
    "database": "database files", "capture": "packet captures", "vpn": "VPN configs",
}
PAYLOAD_LABELS = {
    "webshell": "webshells / backdoors", "executable": "executables .exe/.dll",
    "script": "scripts .ps1/.bat/.sh", "malware_tool": "known offensive tools",
    "binary": "raw binaries",
}
LABEL_META = {
    "malicious_staging": ("Malicious staging", "var(--danger)"),
    "sensitive_exposure": ("Sensitive exposure", "var(--amber)"),
    "intentional_public": ("Intentional public", "var(--green)"),
    "benign_index": ("Benign index", "var(--steel)"),
    "unknown": ("Unknown", "var(--ink-3)"),
}
# Sensitive categories that are outright credentials/keys (for the KPI band).
_CREDKEY = ("env", "credential", "priv_key", "ssh_key")


def _pct(n, total):
    return f"{100 * n / total:.0f}%" if total else "0%"


def _human_bytes(n):
    if not isinstance(n, int):
        return None
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024


def _latest_open_dir_snaps():
    latest = {}
    for s in Snapshot.objects.filter(is_open_dir=True).order_by("fetched_at"):
        latest[s.candidate_id] = s
    return list(latest.values())


def esc(s):
    return html.escape(str(s))


# ---- small render helpers -------------------------------------------------

def bar(label, count, mx, color, *, val=None, pct=None):
    """One readout bar (label | track | value). ``pct`` adds a dim percent."""
    w = (100 * count / mx) if mx else 0
    valtxt = esc(val if val is not None else count)
    if pct is not None:
        valtxt += f' <span class="pct">{esc(pct)}</span>'
    return (f'<div class="bar"><span class="blab">{esc(label)}</span>'
            f'<span class="btrack"><i class="bfill" style="--w:{w:.1f}%;--c:{color}"></i></span>'
            f'<span class="bval">{valtxt}</span></div>')


def chart(bars_html, *, labw=None, valw=None):
    style = []
    if labw:
        style.append(f"--labw:{labw}px")
    if valw:
        style.append(f"--valw:{valw}px")
    st = f' style="{";".join(style)}"' if style else ""
    return f'<div class="chart"{st}>{bars_html}</div>'


def colhead(title, right=""):
    r = f'<span class="cnt">{esc(right)}</span>' if right else ""
    return f'<div class="colhead"><span>{esc(title)}</span>{r}</div>'


def card(num, title, right, body, span, *, feat=False, delay=0.0):
    cls = "card feat sec" if feat else "card sec"
    rt = f'<span class="chr">{esc(right)}</span>' if right else ""
    return (
        f'<section class="{cls}" style="grid-column:span {span};animation-delay:{delay:.2f}s">'
        f'<div class="ch"><span class="snum">{num:02d}</span><h2>{esc(title)}</h2>{rt}</div>'
        f'{body}</section>')


# ---- per-host evidence table ---------------------------------------------

def _file_meta(f):
    """The dim '<size> · <date>' line under a file name (kept short so it never
    clips; the content hash / VirusTotal verdict get their own line, see
    :func:`_file_vt`)."""
    parts = []
    sz = _human_bytes(f.get("size")) if isinstance(f.get("size"), int) else None
    if sz:
        parts.append(esc(sz))
    dt = (f.get("mtime") or "").split("T")[0]
    if dt:
        parts.append(dt)
    return " &middot; ".join(parts)


def _file_vt(f):
    """Clickable content-hash + VirusTotal verdict line for a hashed
    exec/script file. Links to the public VT report for the file's sha256 (a
    hash is not PII); empty for files we never hashed. The verdict sits on its
    own line so it stays legible instead of being ellipsised out of the meta."""
    if f["kind"] != "exec" or not f.get("sha256"):
        return ""
    sha = f["sha256"]
    href = f"https://www.virustotal.com/gui/file/{esc(sha)}"
    vt = f.get("vt")
    if isinstance(vt, dict) and vt.get("found"):
        mal, tot = vt.get("malicious", 0), vt.get("total", 0)
        verdict = (f'<span class="vt mal">VT {mal}/{tot} flagged</span>' if mal
                   else '<span class="vt clean">VT clean</span>')
    else:
        verdict = '<span class="vt">VT lookup</span>'
    return (f'<a class="dfvt" href="{href}" target="_blank" rel="noopener noreferrer" '
            f'title="Look up {esc(sha)} on VirusTotal">'
            f'<span class="dfhash">{esc(sha[:10])}&hellip;</span> {verdict} '
            f'<span class="dfext">&#8599;</span></a>')


def _file_name(f):
    """(display_html, is_alarm). Exec/script files show their real name; data
    files show their real name only under disclosure, else just their type."""
    if f["kind"] == "exec":
        nm = ("&#9888; " if f.get("alarm") else "") + esc(f["name"])
        return nm, bool(f.get("alarm"))
    if f.get("name"):
        return esc(f["name"]), False
    return esc(f.get("ext") or "(no ext)"), False


def _eviz(files):
    """Up-to-two 'notable evidence' tokens for the collapsed row."""
    out = []
    for f in files[:2]:
        if f["kind"] == "exec":
            nm, cls = f["name"], ' class="w"' if f.get("alarm") else ""
        elif f.get("name"):
            nm, cls = f["name"], ""
        else:
            nm, cls = (f.get("ext") or "(no ext)"), ' class="k"'
        disp = nm if len(nm) <= 40 else nm[:39] + "…"
        out.append(f'<code{cls} title="{esc(nm)}">{esc(disp)}</code>')
    return " &middot; ".join(out) or '<span style="color:var(--ink-4)">&mdash;</span>'


def _tags(signals, limit=None):
    out = []
    shown = signals if limit is None else signals[:limit]
    for s in shown:
        warn = " warn" if s.startswith("⚠") else ""
        out.append(f'<span class="tag{warn}">{esc(s)}</span>')
    if limit is not None and len(signals) > limit:
        out.append(f'<span class="tag more">+{len(signals) - limit}</span>')
    return "".join(out)


def _host_table(finv, hcap, n_fhosts, pagesize):
    a = ['<table class="htable"><thead><tr>'
         '<th>Host</th><th>Verdict</th><th class="r">Files</th>'
         '<th class="hide-sm">Signals</th><th>Notable evidence</th></tr></thead><tbody>']
    for i, row in enumerate(finv[:hcap]):
        mal = row["verdict"] == "malicious"
        chip = "mal" if mal else "sen"
        hp = row.get("honeypot")
        hpmark = ' <span class="hp">&#9888; HP</span>' if hp else ""
        a.append(
            f'<tr class="host {chip}" data-i="{i}" tabindex="0" aria-expanded="false">'
            f'<td class="htoken"><span class="cv">&#9656;</span>{esc(row["token"])}{hpmark}</td>'
            f'<td><span class="chip {chip}">{esc(row["verdict"])}</span></td>'
            f'<td class="r hfiles">{row["total"]:,}</td>'
            f'<td class="hide-sm"><div class="tags">{_tags(row["signals"], 2)}</div></td>'
            f'<td class="eviz">{_eviz(row["files"])}</td></tr>')
        # detail row
        dhead = (f'<span class="dv chip {chip}">{esc(row["verdict"])}</span>'
                 f'<span class="dcount">{row["total"]:,} files</span>'
                 f'<span class="dshow">showing {row["shown"]} of {row["total"]:,}</span>'
                 f'{_tags(row["signals"])}')
        notes = ""
        if hp:
            notes += ('<div class="dnote alarm">&#9888; Potential honeypot &mdash; '
                      f'{esc("; ".join(hp["reasons"]))}</div>')
        if not row.get("has_meta"):
            notes += ('<div class="dnote">Names-only listing &mdash; this server '
                      'publishes no file sizes or dates.</div>')
        files_html = []
        for f in row["files"]:
            nm, alarm = _file_name(f)
            meta = _file_meta(f)
            vt_line = _file_vt(f)
            title = f.get("name") or f.get("ext") or ""
            files_html.append(
                f'<div class="dfile{" alarm" if alarm else ""}" title="{esc(title)}">'
                f'<span class="dfn">{nm}</span>'
                f'<span class="dfm">{meta}</span>{vt_line}</div>')
        more = (f'<div class="dmore">+{row["hidden"]:,} more files &mdash; not published '
                'in this export</div>') if row["hidden"] else ""
        a.append(
            f'<tr class="detail" data-for="{i}"><td colspan="5"><div class="dwrap">'
            f'<div class="dhead">{dhead}</div>{notes}'
            f'<div class="dfiles">{"".join(files_html)}</div>{more}</div></td></tr>')
    a.append("</tbody></table>")
    a.append(f'<div class="pager" data-pagesize="{pagesize}"></div>')
    return "".join(a)


# ---- main document build --------------------------------------------------

def build_html(full_names=False):
    n_candidates = Candidate.objects.count()
    n_captured = Candidate.objects.filter(status="captured").count()
    n_error = Candidate.objects.filter(status="error").count()
    n_pending = Candidate.objects.filter(status="pending").count()
    open_dirs = _latest_open_dir_snaps()
    n_open = len(open_dirs)
    n_not_listing = (
        Snapshot.objects.filter(http_status=200, is_open_dir=False)
        .values("candidate").distinct().count()
    )
    validated_total = n_open + n_not_listing

    # Count over the LATEST snapshot per open dir (a re-captured host has several
    # snapshots and would otherwise inflate the totals).
    labels = Counter()
    for s in open_dirs:
        cls = (s.classifications.filter(ruleset_version=RULESET_VERSION)
               .order_by("-classified_at").first())
        if cls:
            labels[cls.label] += 1
    n_classified = sum(labels.values())
    n_sensitive = labels.get("sensitive_exposure", 0) + labels.get("malicious_staging", 0)
    n_malstage = labels.get("malicious_staging", 0)

    sens_dirs, pay_dirs, ext_dirs, server_kinds = Counter(), Counter(), Counter(), Counter()
    interest_dirs = Counter()
    for s in open_dirs:
        server_kinds[s.server_kind or "unknown"] += 1
        for cat in scan_names(s.listing_entries or []):
            interest_dirs[cat] += 1
        cls = s.classifications.order_by("-classified_at").first()
        feats = cls.features if cls else None
        if not feats:
            continue
        for cat, n in (feats.get("sensitive_hits") or {}).items():
            if n:
                sens_dirs[cat] += 1
        for cat, n in (feats.get("payload_hits") or {}).items():
            if n:
                pay_dirs[cat] += 1
        for ext in (feats.get("top_exts") or {}):
            ext_dirs[ext] += 1

    n_webshell = pay_dirs.get("webshell", 0)
    n_credkey = sum(sens_dirs.get(c, 0) for c in _CREDKEY)

    hashed = PayloadHash.objects.exclude(sha256="").count()
    skipped = PayloadHash.objects.filter(sha256="").count()
    vt_found = PayloadHash.objects.filter(vt__found=True).count()
    vt_malicious = PayloadHash.objects.filter(vt__malicious__gt=0).count()
    pay_types = Counter(
        p.name.rsplit(".", 1)[-1].lower()
        for p in PayloadHash.objects.exclude(sha256="") if "." in p.name
    )

    # network profile (unique hosts by ASN org, from Shodan source_meta)
    _seen, _orgs, _countries = set(), [], Counter()
    for s in open_dirs:
        m = s.candidate.source_meta or {}
        ip = m.get("ip") or urlsplit(s.candidate.url).hostname
        if ip in _seen:
            continue
        _seen.add(ip)
        _orgs.append(m.get("org"))
        _countries[m.get("country") or "?"] += 1
    cat_counts, prov_counts = profile_breakdown(_orgs)
    n_hosts_net = sum(cat_counts.values())

    # per-host file inventory (needs a secret salt for non-reversible tokens)
    salt = os.environ.get("REPORT_HOST_SALT", "")
    records = [
        {"url": s.candidate.url,
         "label": (cls := s.classifications.order_by("-classified_at").first()) and cls.label,
         "features": cls.features if cls else {},
         "entries": s.listing_entries or [],
         "raw_html_sha256": s.raw_html_sha256}
        for s in open_dirs if s.classifications.exists()
    ]
    finv, n_fhosts, n_hp = [], 0, 0
    if salt and records:
        fhashes = {}
        for ph in PayloadHash.objects.exclude(sha256=""):
            fhashes[(urlsplit(ph.url).hostname or "", ph.name)] = {
                "sha256": ph.sha256, "tlsh": ph.tlsh, "vt": ph.vt}
        finv, n_fhosts = host_file_inventory(
            records, salt, hashes=fhashes,
            max_files=30 if full_names else 8, disclose=full_names)
        n_hp = sum(1 for r in finv if r.get("honeypot"))

    p = []
    a = p.append

    # ---- masthead: title + meta + capture pipeline
    fp_rate = _pct(n_not_listing, validated_total) if validated_total else "—"
    a('<header class="top sec"><div>'
      '<div class="eyebrow">Open-Directory Exposure &mdash; Field Report</div>'
      '<h1 class="title">patefact</h1>'
      '<p class="dek">Measuring what the public internet leaves standing open.</p>'
      '</div><div class="masthead-r"><div class="meta">'
      f'<span>Generated&nbsp;<b>{timezone.now():%Y-%m-%d %H:%MZ}</b></span>'
      f'<span>Ruleset&nbsp;<b>v{RULESET_VERSION}</b></span>'
      '<span class="stamp">Aggregate &middot; No Addresses</span></div>'
      '<div class="pipe">'
      f'<span class="pstep"><b class="cnum">{n_candidates:,}</b><span class="plab">Discovered</span></span>'
      '<span class="parr">&rarr;</span>'
      f'<span class="pstep"><b class="cnum">{n_captured:,}</b><span class="plab">Captured off-IP</span></span>'
      '<span class="parr">&rarr;</span>'
      f'<span class="pstep"><b class="cnum">{n_open:,}</b><span class="plab">Validated dirs</span></span>'
      '<span class="parr">&middot;</span>'
      f'<span class="pstep pfp"><b>{fp_rate}</b><span class="plab">False-positive</span></span>'
      '</div></div></header>')

    # ---- KPI band
    def kpi(value, label, cls=""):
        return (f'<div class="kpi {cls}"><span class="kn cnum">{esc(value)}</span>'
                f'<span class="kl">{esc(label)}</span></div>')
    sens_pct = f'&thinsp;/&thinsp;{_pct(n_sensitive, n_classified)}' if n_classified else ""
    a('<section class="kpis sec" style="animation-delay:.05s">')
    a(kpi(f"{n_open:,}", "Validated open dirs"))
    a(f'<div class="kpi amber"><span class="kn"><span class="cnum">{n_sensitive:,}</span>'
      f'<span class="kx">{sens_pct}</span></span><span class="kl">Sensitive / malicious</span></div>')
    a(kpi(f"{n_malstage:,}", "Malicious staging dirs", "red"))
    a(kpi(f"{n_webshell:,}", "Confirmed webshells", "red"))
    a(kpi(f"{n_credkey:,}", "Credential & key exposures", "amber"))
    a(kpi(f"{n_hp:,}", "Suspected honeypots"))
    a("</section>")

    a('<div class="deck">')

    # ---- 01 classification
    if n_classified:
        rows = []
        for lab, n in labels.most_common():
            name, color = LABEL_META.get(lab, (lab, "var(--ink-3)"))
            rows.append(bar(name, n, max(labels.values()), color,
                            val=f"{n:,}", pct=_pct(n, n_classified)))
        body = (f'<div class="cb"><p class="sub">Deterministic classifier, ruleset '
                f'<code>v{RULESET_VERSION}</code>. Two thirds are benign indexes; one '
                f'third leak something they shouldn\'t.</p>{chart("".join(rows), labw=118, valw=78)}'
                '<p class="note">Every verdict stores its full feature vector and is '
                'reproducible from the listing alone.</p></div>')
    else:
        body = ('<div class="cb"><p class="note">No classifications yet &mdash; run '
                '<code>manage.py classify</code>.</p></div>')
    a(card(1, "Classification", f"rules-first · {n_classified:,} dirs", body, 4, delay=.10))

    # ---- 02 what was exposed (feature)
    sens_rows = "".join(
        bar(SENSITIVE_LABELS.get(c, c), n, sens_dirs.most_common(1)[0][1], "var(--amber)")
        for c, n in sens_dirs.most_common()) if sens_dirs else ""
    atk_rows = "".join(
        bar(PAYLOAD_LABELS.get(c, c), n, pay_dirs.most_common(1)[0][1], "var(--danger)")
        for c, n in pay_dirs.most_common()) if pay_dirs else ""
    mine_rows = "".join(
        bar(INTEREST_LABELS.get(c, c), n, interest_dirs.most_common(1)[0][1], "var(--rose)")
        for c, n in interest_dirs.most_common()) if interest_dirs else ""
    left = ('<div class="subgroup">' + colhead("Sensitive data", "amber")
            + (chart(sens_rows, labw=100, valw=40) if sens_rows
               else '<p class="note">None detected.</p>') + "</div>")
    right = '<div class="subgroup">' + colhead("Attacker / executable content", "red")
    right += (chart(atk_rows, labw=118, valw=40) if atk_rows
              else '<p class="note">None detected.</p>')
    right += '<div style="margin-top:22px">' + colhead("Heuristic inventory mining", "filenames only")
    right += (chart(mine_rows, labw=118, valw=40) if mine_rows
              else '<p class="note">None detected.</p>')
    right += "</div></div>"
    a(card(2, "What Was Exposed", "dirs containing signal",
           f'<div class="cb split2">{left}{right}</div>', 8, feat=True, delay=.15))

    # ---- 03 network profile
    if n_hosts_net:
        ncat = "".join(
            bar(CATEGORY_DISPLAY[c], cat_counts[c], max(cat_counts.values()), _CAT_COLOR[c],
                val=f"{cat_counts[c]:,}", pct=_pct(cat_counts[c], n_hosts_net))
            for c in sorted(CATEGORY_ORDER, key=lambda c: -cat_counts.get(c, 0)) if cat_counts.get(c))
        tp = prov_counts.most_common(8)
        nprov = "".join(bar(pv, n, tp[0][1], "var(--blue)", val=f"{n:,}") for pv, n in tp)
        tc = _countries.most_common(10)
        ncnt = "".join(bar(c, n, tc[0][1], "var(--ink-2)", val=f"{n:,}") for c, n in tc)
        note = ('<div class="cb" style="padding-top:0"><p class="note">Open directories '
                'cluster on <strong>cloud &amp; hosting infrastructure</strong>, not home '
                'connections &mdash; misconfigured deployments, not compromised laptops.</p></div>')
        body = (f'<div class="cb split3">'
                f'<div>{colhead("Network type")}{chart(ncat, labw=120, valw=82)}</div>'
                f'<div>{colhead("Top providers")}{chart(nprov, labw=150, valw=40)}</div>'
                f'<div>{colhead("Top countries")}{chart(ncnt, labw=34, valw=44)}</div>'
                f'</div>{note}')
    else:
        body = ('<div class="cb"><p class="note">No network data &mdash; hosts carry no '
                'ASN/org metadata in <code>source_meta</code>.</p></div>')
    a(card(3, "Network Profile", "ASN owner via Shodan · unique hosts", body, 12, delay=.20))

    # ---- 04 composition
    if ext_dirs:
        top = ext_dirs.most_common(12)
        ftypes = "".join(bar(e, n, top[0][1], "var(--blue)", val=f"{n:,}") for e, n in top)
        ftypes = colhead("File types") + chart(ftypes, labw=42, valw=44)
    else:
        ftypes = colhead("File types") + '<p class="note">No file-type data.</p>'
    if server_kinds:
        sk = server_kinds.most_common()
        servers = "".join(bar(k, n, sk[0][1], "var(--violet)", val=f"{n:,}") for k, n in sk)
        servers = (colhead("Server software") + chart(servers, labw=56, valw=52)
                   + '<p class="note" style="margin-top:16px">Apache\'s <code>mod_autoindex</code> '
                   'default dominates &mdash; the exposure is overwhelmingly a <strong>left-on '
                   'directory listing</strong>, not a purpose-built file server.</p>')
    else:
        servers = colhead("Server software") + '<p class="note">No server data.</p>'
    a(card(4, "Composition", "dirs containing",
           f'<div class="cb split2"><div>{ftypes}</div><div>{servers}</div></div>', 5, delay=.25))

    # ---- 05 read (narrative synthesis)
    if n_classified and n_sensitive:
        onein = max(2, round(n_classified / n_sensitive))
        top_sens = ", ".join(SENSITIVE_LABELS.get(c, c) for c, _ in sens_dirs.most_common(3)) \
            or "sensitive files"
        n_git = sens_dirs.get("git", 0)
        n_offtool = pay_dirs.get("malware_tool", 0)
        rd = (f'<p class="sub" style="margin:0"><strong>Roughly 1 in {onein} open directories '
              f'leaks something sensitive.</strong> The volume sits in {top_sens} &mdash; the '
              'raw material for follow-on compromise.</p>')
        if n_credkey or n_git:
            rd += (f'<p class="sub" style="margin:14px 0 0"><strong>{n_credkey} dirs</strong> '
                   'expose credentials or keys outright (.env, credential files, private &amp; '
                   f'SSH keys). <strong>{n_git}</strong> serve a live <code>.git</code> tree '
                   '&mdash; full source and history.</p>')
        if n_webshell or n_offtool:
            rd += (f'<p class="note"><span class="alarmtxt">&#9888; {n_webshell} confirmed '
                   f'webshells / backdoors</span> and {n_offtool} known offensive tools mean a '
                   'subset of these hosts are already <em>operated</em>, not merely leaking.</p>')
        body = f'<div class="cb">{rd}</div>'
    else:
        body = ('<div class="cb"><p class="sub" style="margin:0">No sensitive exposures '
                'classified yet.</p></div>')
    a(card(5, "Read", "", body, 3, delay=.30))

    # ---- 06 payload analysis
    if hashed or skipped:
        minis = [(f"{hashed:,}", "Payloads hashed", "")]
        if skipped:
            minis.append((f"{skipped:,}", "Skipped · cap / unreachable", ""))
        if PayloadHash.objects.filter(vt__isnull=False).exists():
            minis.append((f"{vt_found:,}", "Known to VirusTotal", "cool"))
            minis.append((f"{vt_malicious:,}", "Flagged malicious", "good" if not vt_malicious else ""))
        mini_html = "".join(
            f'<div class="m {c}"><div class="mn cnum">{esc(v)}</div><div class="ml">{esc(l)}</div></div>'
            for v, l, c in minis)
        pills = "".join(f'<span class="pill">.{esc(e)}&thinsp;<b>&times;{n}</b></span>'
                        for e, n in pay_types.most_common())
        pillrow = f'<div style="margin-top:14px">{pills}</div>' if pills else ""
        note = ('<p class="note">Hashed payloads resolve to legitimate software/config scripts '
                '&mdash; consistent with the corpus being <em>exposures / misconfigurations</em> '
                'rather than active malware staging.</p>') if (vt_found and not vt_malicious) else ""
        body = (f'<div class="cb"><p class="sub">Executable/script files (never media, archives '
                'or data) are fetched on the disposable worker, hashed, and discarded &mdash; only '
                f'the hash is kept.</p><div class="mini">{mini_html}</div>{pillrow}{note}</div>')
    else:
        body = ('<div class="cb"><p class="note">No payloads hashed yet.</p></div>')
    a(card(6, "Payload Analysis", "exec/script allowlist only", body, 4, delay=.35))

    # ---- 07 per-host file inventory (expandable table)
    hcap = min(120 if full_names else 12, n_fhosts)
    pagesize = 20
    if salt and finv:
        if full_names:
            intro = ('<strong>Full-disclosure mode</strong> &mdash; every file listed by its '
                     'real name (data files included). Host addresses are still withheld '
                     '(salted-HMAC tokens), but <span class="alarmtxt">filenames can contain '
                     'PII</span>; review before publishing.')
        else:
            intro = ('File-level evidence per <strong>pseudonymous host</strong> (salted-HMAC '
                     'token &mdash; stable, non-reversible). Executable/script names are shown; '
                     'data filenames are withheld as potential PII. <span class="alarmtxt">'
                     '&#9888; marks confirmed webshells or VirusTotal-flagged files.</span>')
        if n_hp:
            intro += (f' <span class="alarmtxt">{n_hp} host(s) flagged as suspected honeypots</span> '
                      '&mdash; bait listings fanned byte-identically across ports.')
        body = (f'<div class="cb"><p class="sub">{intro} Click a row to expand its file listing.</p>'
                f'{_host_table(finv, hcap, n_fhosts, pagesize)}</div>')
    elif not salt:
        body = ('<div class="cb"><p class="note">Per-host inventory omitted &mdash; set '
                '<code>REPORT_HOST_SALT</code> to emit non-reversible host tokens.</p></div>')
    else:
        body = '<div class="cb"><p class="note">No flagged hosts.</p></div>'
    right = (f"worst {hcap:,} of {n_fhosts:,}" + (" · paged" if hcap > pagesize else "")) \
        if (salt and finv) else ""
    a(card(7, "Per-Host File Inventory", right, body, 12, delay=.40))

    a("</div>")  # /deck

    # ---- footer
    a('<footer class="sec">'
      '<div class="classline">Aggregate &middot; No Host Addresses &middot; Research Use Only</div>'
      f'<div class="fine">Deterministic throughout &mdash; feature extractor '
      f'<code>v{EXTRACTOR_VERSION}</code>, ruleset <code>v{RULESET_VERSION}</code>. '
      f'{n_pending:,} candidates pending capture &middot; {n_error:,} errored. All captures '
      'originate off-IP from a disposable, self-destructing cloud worker; untrusted HTML is '
      'parsed off-box and only structured data returns. Every classification stores its full '
      'feature vector; any verdict can be reproduced.</div></footer>')

    return "\n".join(p)


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>patefact &mdash; exposure field report</title>
<style>
:root{
  --bg:#0d0c0a; --bg-elev:#16130d; --bg-cell:#131009; --bg-hi:#1b160d;
  --ink:#ece4d3; --ink-2:#c2baa8; --ink-3:#847c6e; --ink-4:#5f594e;
  --line:#26221b; --line-2:#39332a;
  --amber:#f2a63b; --amber-2:#b9821f;
  --danger:#e5544e; --steel:#727a71; --green:#68b488; --blue:#6aa6cf; --violet:#a48ccb; --rose:#e2698a;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua","Hoefler Text",Georgia,serif;
  --mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,"DejaVu Sans Mono",Consolas,monospace;
}
*{box-sizing:border-box}
html{color-scheme:dark}
::selection{background:var(--amber);color:#1a1305}
body{
  margin:0;color:var(--ink);font-family:var(--mono);font-size:13px;line-height:1.5;
  letter-spacing:.01em;-webkit-font-smoothing:antialiased;min-height:100vh;
  background:radial-gradient(1200px 560px at 50% -260px,rgba(242,166,59,.08),transparent 68%),var(--bg);
}
body::before{content:"";position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.05;
  mix-blend-mode:soft-light;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");}
.frame{position:fixed;inset:12px;border:1px solid var(--line);z-index:2;pointer-events:none}
.wrap{position:relative;z-index:3;max-width:1400px;margin:0 auto;padding:46px 40px 80px}
a{color:var(--amber);text-decoration:none;border-bottom:1px solid rgba(242,166,59,.35)}
a:hover{color:var(--ink);border-bottom-color:var(--amber)}
strong{color:var(--ink);font-weight:600}em{color:var(--ink-2);font-style:italic}
code{font-family:var(--mono);color:var(--amber);background:rgba(242,166,59,.09);padding:1px 5px;border-radius:3px;font-size:.9em}

/* ---- masthead ---- */
.top{display:grid;grid-template-columns:1fr auto;gap:40px;align-items:end;padding-bottom:24px;
  border-bottom:1px solid var(--line-2);position:relative}
.top::after{content:"";position:absolute;left:0;right:0;bottom:-4px;border-top:1px solid var(--line)}
.eyebrow{display:flex;align-items:center;gap:12px;font-size:10.5px;letter-spacing:.34em;
  text-transform:uppercase;color:var(--amber)}
.eyebrow::before{content:"";width:34px;height:2px;background:var(--amber)}
.title{font-family:var(--serif);font-weight:600;font-size:clamp(52px,7vw,88px);line-height:.9;
  letter-spacing:-.02em;margin:14px 0 0}
.dek{font-family:var(--serif);font-style:italic;font-size:19px;color:var(--ink-2);margin:12px 0 0;max-width:40ch}
.masthead-r{text-align:right;display:flex;flex-direction:column;gap:14px;align-items:flex-end}
.meta{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px 20px;font-size:10.5px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--ink-3)}
.meta b{color:var(--ink);font-weight:600}
.stamp{border:1px solid var(--amber-2);color:var(--amber);padding:2px 10px;letter-spacing:.17em}
.pipe{display:flex;align-items:center;gap:12px;font-size:11px;color:var(--ink-3);letter-spacing:.04em}
.pipe b{display:block;font-family:var(--serif);font-size:22px;color:var(--ink);letter-spacing:0;line-height:1;
  font-variant-numeric:tabular-nums}
.pipe .pstep{text-align:center}
.pipe .plab{display:block;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);margin-top:5px}
.pipe .parr{color:var(--line-2);font-size:14px}
.pipe .pfp b{color:var(--amber)}

/* ---- kpi strip ---- */
.kpis{display:grid;grid-template-columns:repeat(6,1fr);border:1px solid var(--line-2);background:var(--line);
  gap:1px;margin:24px 0 0}
.kpi{background:var(--bg-cell);padding:18px 18px 15px;position:relative;overflow:hidden}
.kpi .kn{display:block;font-family:var(--serif);font-size:42px;font-weight:600;line-height:.95;
  letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.kpi .kl{display:block;margin-top:9px;font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--ink-3);line-height:1.4}
.kpi .kx{color:var(--ink-4)}
.kpi.amber .kn{color:var(--amber)} .kpi.red .kn{color:var(--danger)}
.kpi::before{content:"";position:absolute;top:0;left:0;width:14px;height:14px;opacity:.9}
.kpi.amber::before{border-top:2px solid var(--amber);border-left:2px solid var(--amber)}
.kpi.red::before{border-top:2px solid var(--danger);border-left:2px solid var(--danger)}

/* ---- panel deck ---- */
.deck{display:grid;grid-template-columns:repeat(12,1fr);gap:16px;margin-top:16px}
.card{border:1px solid var(--line-2);background:var(--bg-elev);display:flex;flex-direction:column;min-width:0}
.card.feat{box-shadow:inset 0 2px 0 -1px var(--amber-2)}
.ch{display:flex;align-items:baseline;gap:11px;padding:13px 16px;border-bottom:1px solid var(--line);min-height:46px}
.ch .snum{font-size:10.5px;color:var(--amber);letter-spacing:.1em;font-variant-numeric:tabular-nums}
.ch h2{font-family:var(--mono);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.2em;margin:0;white-space:nowrap}
.ch .chr{margin-left:auto;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3);text-align:right}
.cb{padding:16px;flex:1}
.sub{color:var(--ink-2);font-size:11.5px;margin:0 0 14px;line-height:1.55}
.note{color:var(--ink-3);font-size:10.5px;margin:12px 0 0;line-height:1.5}
.alarmtxt{color:var(--danger)}
.colhead{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3);margin:0 0 11px;
  display:flex;justify-content:space-between}
.colhead .cnt{color:var(--ink-4)}
.split2{display:grid;grid-template-columns:1fr 1fr;gap:26px}
.split3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:26px}
.subgroup+.subgroup{margin-top:20px}

/* ---- bars ---- */
.chart{display:flex;flex-direction:column;gap:6px}
.bar{display:grid;grid-template-columns:var(--labw,110px) 1fr var(--valw,58px);align-items:center;gap:12px}
.blab{font-size:11px;text-align:right;color:var(--ink-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.btrack{height:15px;background:var(--bg);border:1px solid var(--line);position:relative;overflow:hidden}
.bfill{display:block;height:100%;width:var(--w);background:var(--c);transform-origin:left;
  animation:grow .9s cubic-bezier(.2,.75,.25,1) both;will-change:transform;box-shadow:0 0 12px -4px var(--c)}
.bval{font-size:11px;color:var(--ink);font-variant-numeric:tabular-nums;white-space:nowrap}
.bval .pct{color:var(--ink-3)}

/* ---- payload mini stats ---- */
.mini{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--line);background:var(--line);gap:1px}
.mini .m{background:var(--bg-cell);padding:13px 14px}
.mini .mn{font-family:var(--serif);font-size:28px;font-weight:600;line-height:1;font-variant-numeric:tabular-nums}
.mini .ml{font-size:9px;letter-spacing:.11em;text-transform:uppercase;color:var(--ink-3);margin-top:7px;line-height:1.35}
.mini .m.cool .mn{color:var(--blue)} .mini .m.good .mn{color:var(--green)}
.pill{display:inline-block;font-size:10.5px;color:var(--ink-2);background:var(--bg-cell);
  border:1px solid var(--line);padding:2px 9px;margin:5px 5px 0 0}
.pill b{color:var(--amber)}

/* ---- host evidence table ---- */
.htable{width:100%;border-collapse:collapse;font-size:11.5px}
.htable th{font-size:9.5px;letter-spacing:.15em;text-transform:uppercase;color:var(--ink-3);font-weight:600;
  text-align:left;padding:0 14px 11px;border-bottom:1px solid var(--line-2)}
.htable th.r,.htable td.r{text-align:right}
.htable td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:top}
.htable tr:last-child td{border-bottom:none}
.htable tbody tr{transition:background .12s}
.htable tbody tr:hover{background:var(--bg-hi)}
.htoken{color:var(--ink);letter-spacing:.03em;white-space:nowrap;position:relative;padding-left:11px}
.htoken::before{content:"";position:absolute;left:0;top:2px;bottom:2px;width:2px;background:var(--amber)}
tr.mal .htoken::before{background:var(--danger)}
.hp{color:var(--danger);font-size:9px;letter-spacing:.1em}
.chip{display:inline-block;font-size:9px;letter-spacing:.13em;text-transform:uppercase;padding:2px 7px;border:1px solid;font-weight:600;white-space:nowrap}
.chip.mal{color:var(--danger);border-color:var(--danger)}
.chip.sen{color:var(--amber);border-color:var(--amber-2)}
.hfiles{font-variant-numeric:tabular-nums;color:var(--ink);white-space:nowrap}
.tags{display:flex;flex-wrap:wrap;gap:4px}
.tag{font-size:9.5px;color:var(--ink-3);background:var(--bg-cell);border:1px solid var(--line);padding:1px 7px;white-space:nowrap}
.tag.warn{color:var(--danger);border-color:rgba(229,84,78,.42)}
.tag.more{color:var(--ink-4);border-style:dashed}
.eviz{color:var(--ink-2);line-height:1.5}
.eviz .w{color:var(--danger)}
.eviz .k{color:var(--blue)}

/* expandable detail */
.htable tr.host{cursor:pointer}
.htable tr.host .cv{display:inline-block;color:var(--ink-3);font-size:9px;margin-right:8px;
  transition:transform .15s,color .15s;transform:translateY(-1px)}
.htable tr.host[aria-expanded="true"] .cv{transform:rotate(90deg);color:var(--amber)}
.htable tr.host[aria-expanded="true"]{background:var(--bg-hi)}
.htable tr.host:focus-visible{outline:1px solid var(--amber-2);outline-offset:-1px}
.htable tr.detail{display:none}
.htable tr.detail.open{display:table-row}
.htable tr.detail>td{padding:0 14px;background:var(--bg);border-bottom:1px solid var(--line-2)}
.dwrap{padding:14px 0 16px}
.dhead{display:flex;flex-wrap:wrap;align-items:center;gap:7px;margin-bottom:12px}
.dhead .dcount{font-size:10.5px;color:var(--ink-2);font-variant-numeric:tabular-nums;letter-spacing:.04em}
.dhead .dshow{font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3)}
.dnote{font-size:10.5px;color:var(--ink-3);font-style:italic;margin-bottom:10px;line-height:1.5}
.dnote.alarm{color:var(--danger);font-style:normal}
.dfiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:1px;background:var(--line);
  border:1px solid var(--line)}
.dfile{background:var(--bg-cell);padding:6px 10px;min-width:0;overflow:hidden}
.dfn{display:block;font-size:11px;color:var(--ink-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dfile.alarm .dfn{color:var(--danger)}
.dfm{display:block;font-size:9.5px;color:var(--ink-4);font-variant-numeric:tabular-nums;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;margin-top:2px;min-height:12px}
a.dfvt{display:block;margin-top:3px;font-size:9.5px;letter-spacing:.02em;border-bottom:none;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
a.dfvt:hover{border-bottom:none}
a.dfvt:hover .dfhash,a.dfvt:hover .vt{text-decoration:underline}
.dfhash{color:var(--blue)}
.dfvt .vt{color:var(--ink-3)}
.dfvt .vt.clean{color:var(--green)}
.dfvt .vt.mal{color:var(--danger)}
.dfvt .dfext{color:var(--ink-4)}
.dmore{font-size:10.5px;color:var(--ink-3);font-style:italic;margin-top:10px}

/* ---- pager ---- */
.pager{display:none;align-items:center;justify-content:flex-end;gap:14px;margin-top:16px}
.pager.on{display:flex}
.pager button{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--ink);background:var(--bg-cell);border:1px solid var(--line-2);padding:7px 15px;cursor:pointer;
  transition:border-color .15s,color .15s}
.pager button:hover:not(:disabled){border-color:var(--amber-2);color:var(--amber)}
.pager button:disabled{color:var(--ink-3);cursor:default;opacity:.45}
.pager .pgi{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);
  font-variant-numeric:tabular-nums;min-width:118px;text-align:center}

/* ---- footer ---- */
footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--line-2)}
.classline{display:flex;align-items:center;gap:11px;font-size:10.5px;letter-spacing:.23em;
  text-transform:uppercase;color:var(--amber);margin-bottom:11px}
.classline::before,.classline::after{content:"";flex:0 0 auto;width:7px;height:7px;background:var(--amber);transform:rotate(45deg)}
.classline::after{margin-left:auto}
.fine{font-size:10.5px;color:var(--ink-3);max-width:96ch;line-height:1.55}

@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.sec{animation:rise .5s cubic-bezier(.2,.7,.2,1) both}

@media (max-width:1100px){
  .kpis{grid-template-columns:repeat(3,1fr)}
  .deck>*{grid-column:1 / -1 !important}
  .split3{grid-template-columns:1fr}
}
@media (max-width:760px){
  .wrap{padding:34px 18px 60px}
  .top{grid-template-columns:1fr;gap:22px}
  .masthead-r{text-align:left;align-items:flex-start}
  .meta{justify-content:flex-start}
  .kpis{grid-template-columns:1fr 1fr}
  .split2{grid-template-columns:1fr}
  .htable .hide-sm{display:none}
  .frame{inset:7px}
}
@media (prefers-reduced-motion:reduce){.sec,.bfill{animation:none!important}.bfill{transform:none!important}}
</style>
</head>
<body>
<div class="frame"></div>
<div class="wrap">
<!--BODY-->
</div>
<script>
(function(){
  try{
    if(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    document.querySelectorAll('.cnum').forEach(function(el){
      var m=/^(\\D*)(\\d[\\d,]*)(.*)$/.exec(el.textContent.trim()); if(!m) return;
      var pre=m[1], target=parseInt(m[2].replace(/,/g,''),10), suf=m[3];
      if(!isFinite(target)||target>2000000) return;
      var t0=null, dur=850;
      function step(ts){ if(!t0)t0=ts; var p=Math.min((ts-t0)/dur,1);
        var v=Math.round(target*(1-Math.pow(1-p,3)));
        el.textContent=pre+v.toLocaleString()+suf; if(p<1)requestAnimationFrame(step); }
      el.textContent=pre+'0'+suf; requestAnimationFrame(step);
    });
  }catch(e){}
})();
(function(){
  // expandable host rows
  try{
    document.querySelectorAll('.htable tr.host').forEach(function(row){
      function toggle(){
        var det=row.nextElementSibling, open=row.getAttribute('aria-expanded')==='true';
        row.setAttribute('aria-expanded', open?'false':'true');
        if(det&&det.classList.contains('detail')) det.classList.toggle('open', !open);
      }
      row.addEventListener('click', toggle);
      row.addEventListener('keydown', function(e){
        if(e.key==='Enter'||e.key===' '){ e.preventDefault(); toggle(); }
      });
    });
  }catch(e){}
})();
(function(){
  // pager over host-row pairs
  try{
    var table=document.querySelector('.htable');
    var pager=document.querySelector('.pager');
    if(!table||!pager) return;
    var hosts=[].slice.call(table.querySelectorAll('tbody tr.host'));
    var size=parseInt(pager.getAttribute('data-pagesize')||'20',10);
    var pages=Math.ceil(hosts.length/size);
    if(pages<=1) return;
    var page=0;
    var prev=document.createElement('button'); prev.textContent='< Prev';
    var ind=document.createElement('span'); ind.className='pgi';
    var next=document.createElement('button'); next.textContent='Next >';
    pager.appendChild(prev); pager.appendChild(ind); pager.appendChild(next);
    pager.classList.add('on');
    function render(){
      hosts.forEach(function(h,i){
        var show=(i>=page*size && i<(page+1)*size);
        h.style.display=show?'':'none';
        h.setAttribute('aria-expanded','false');
        var det=h.nextElementSibling;
        if(det&&det.classList.contains('detail')) det.classList.remove('open');
      });
      ind.textContent='Page '+(page+1)+' of '+pages;
      prev.disabled=(page===0); next.disabled=(page===pages-1);
    }
    prev.onclick=function(){ if(page>0){page--; render(); table.scrollIntoView({block:'start'});} };
    next.onclick=function(){ if(page<pages-1){page++; render(); table.scrollIntoView({block:'start'});} };
    render();
  }catch(e){}
})();
</script>
</body>
</html>
"""


def main():
    full_names = "--full-names" in sys.argv   # operator opt-in: unredacted data-file names
    paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    doc = PAGE.replace("<!--BODY-->", build_html(full_names=full_names))
    if paths and paths[0] not in ("-", "/dev/stdout"):
        with open(paths[0], "w") as f:
            f.write(doc)
        print(f"wrote {paths[0]} ({len(doc)} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(doc)


if __name__ == "__main__":
    main()
