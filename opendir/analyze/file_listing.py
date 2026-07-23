"""Per-host file-level inventory for the PUBLIC report.

Turns each origin host into a pseudonymous token and a capped list of its most
notable files, under a strict disclosure policy so the report can *show the
research is real* without re-leaking victims or pointing at live hosts:

- **Host identity** -> a SALTED HMAC token (``host-7f3a2c``). A bare hash of an
  IPv4 is reversible (the address space is tiny), so we HMAC the origin host
  with a secret salt: the token is stable per host and groups its files, but
  cannot be turned back into an address.
- **Executable / script / webshell files** (IOCs, per ``opendir.payload.select``)
  -> shown with their REAL name + size + date + content hashes (sha256/tlsh/VT)
  when we hashed them. Publishing malware/webshell names+hashes is standard
  threat-intel evidence, not victim data.
- **Every other file** (data files -- ``.sql`` / ``.env`` / spreadsheets / media
  -- whose NAME can itself be PII) -> shown as TYPE + size + date only. The
  filename is never emitted.

Nothing in the returned structure contains a hostname, IP, port, or path.
"""
import hashlib
import hmac
from collections import Counter
from urllib.parse import urlsplit

from opendir.payload.select import (
    _is_payload_name, _extension, WEBSHELL_NAME_RE, WEB_SCRIPT_EXTS,
)
from opendir.analyze.inventory import _COMPILED, _BIG_FILE_BYTES
from opendir.analyze.hosts import _signals_for, SIGNAL_LABELS
from opendir.analyze import honeypot

_VERDICT = {"malicious_staging": "malicious", "sensitive_exposure": "sensitive"}
_SEV = {"malicious": 0, "sensitive": 1}


def host_token(address: str, salt: str) -> str:
    """Stable, non-reversible pseudonym for an origin host.

    HMAC-SHA256(salt, address) truncated to a short hex token. The secret salt
    is what makes it non-reversible -- without it, an unsalted hash of an IPv4
    could be brute-forced across the whole address space.
    """
    if not salt:
        raise ValueError("a secret salt is required (an unsalted IP hash is reversible)")
    mac = hmac.new(salt.encode(), address.encode(), hashlib.sha256).hexdigest()
    return "host-" + mac[:6]


def _sensitive_data_name(name: str) -> bool:
    low = name.lower()
    return any(r.search(low) for regexes in _COMPILED.values() for r in regexes)


def _is_alarm(name: str, vt) -> bool:
    """A true danger marker (not merely 'is an executable'): a *web script*
    named like a webshell/backdoor (so ``Xshell.exe`` / ``PowerShell`` don't
    match), or a content hash flagged malicious by VirusTotal."""
    low = name.lower()
    if _extension(low) in WEB_SCRIPT_EXTS and WEBSHELL_NAME_RE.search(low):
        return True
    return bool(isinstance(vt, dict) and vt.get("malicious"))


def _rank(entry, hashes_by_name) -> int:
    """Notability rank (lower = more notable), for capping the per-host list.
    Genuine threats/secrets outrank benign executables (e.g. software mirrors)."""
    name = str(entry.get("name", ""))
    size = entry.get("size") if isinstance(entry.get("size"), int) else 0
    payload = _is_payload_name(name)
    if payload and _is_alarm(name, (hashes_by_name.get(name) or {}).get("vt")):
        return 0                       # webshell / VT-flagged-malicious
    if _sensitive_data_name(name):
        return 1                       # data file whose name suggests secrets/PII
    if payload:
        return 2                       # other executable/script (often benign SW)
    if size >= _BIG_FILE_BYTES:
        return 3                       # large exposed file
    return 4                           # ordinary file


def _file_row(entry, hashes_by_name, disclose: bool = False) -> dict:
    """One file row. Executable/script files always keep their name (PII-safe)
    plus hashes when we have them. Other (data) files show TYPE + size + date
    only -- UNLESS ``disclose`` is set (operator-chosen full-disclosure mode),
    in which case their real name is included too. ``alarm`` is the danger flag.
    """
    name = str(entry.get("name", ""))
    ext = _extension(name.lower())
    size = entry.get("size") if isinstance(entry.get("size"), int) else None
    mtime = entry.get("mtime") or None
    if _is_payload_name(name):
        h = hashes_by_name.get(name) or {}
        row = {"kind": "exec", "name": name, "ext": ext, "size": size, "mtime": mtime,
               "alarm": _is_alarm(name, h.get("vt"))}
        if h:
            row["sha256"] = h.get("sha256") or None
            row["tlsh"] = h.get("tlsh") or None
            row["vt"] = h.get("vt")
        return row
    row = {"kind": "data", "ext": ext or "(no ext)", "size": size, "mtime": mtime}
    if disclose:
        row["name"] = name
    return row


def host_file_inventory(records, salt, *, hashes=None, max_files: int | None = 12,
                        flagged_only: bool = True, disclose: bool = False):
    """Build the per-host file inventory for the report.

    ``records``: iterable of ``{"url", "label", "entries"}`` (one per captured
    directory). ``hashes``: optional ``{(hostname, filename): {"sha256","tlsh",
    "vt"}}`` from PayloadHash, joined per origin host. ``max_files=None`` lists
    every file (no cap). ``disclose=True`` includes data-file names too
    (operator-chosen full disclosure) -- the default withholds them.

    Returns ``(rows, total_hosts)`` where each row is::

        {"token","verdict","signals":[friendly,...],"files":[<row>...],
         "shown":int,"total":int,"hidden":int,"has_meta":bool,
         "honeypot":{"flag":True,"reasons":[...]}|None}

    ranked worst-first. ``signals`` is the address-free semantic summary
    (".env secrets", "SSH keys", ...) derived from classifier signals + name
    mining. No address, port, or path ever appears; data-file names appear only
    under ``disclose=True``.
    """
    hashes = hashes or {}
    by_host: dict[str, dict] = {}
    for rec in records:
        host = urlsplit(rec["url"]).hostname or ""
        verdict = _VERDICT.get(rec.get("label"))
        bucket = by_host.setdefault(host, {"verdict": None, "files": [], "sig": set(),
                                           "ports": set(), "hashes": Counter()})
        if verdict and (bucket["verdict"] is None
                        or _SEV[verdict] < _SEV[bucket["verdict"]]):
            bucket["verdict"] = verdict
        bucket["sig"] |= _signals_for(rec.get("features") or {}, rec.get("entries"))
        bucket["ports"].add(urlsplit(rec["url"]).port)
        if rec.get("raw_html_sha256"):
            bucket["hashes"][rec["raw_html_sha256"]] += 1
        for e in rec.get("entries") or []:
            if not e.get("is_dir"):
                bucket["files"].append(e)

    rows = []
    for host, data in by_host.items():
        if flagged_only and data["verdict"] is None:
            continue
        hashes_by_name = {name: h for (hhost, name), h in hashes.items() if hhost == host}
        files = data["files"]
        ranked = sorted(files, key=lambda e: (_rank(e, hashes_by_name),
                                              -(e.get("size") or 0)))
        notable = ranked if max_files is None else ranked[:max_files]
        safe_rows = [_file_row(e, hashes_by_name, disclose=disclose) for e in notable]

        ports = {p for p in data["ports"] if p}
        identical = max(data["hashes"].values()) if data["hashes"] else 1
        hp_flag, _hp_score, hp_reasons = honeypot.assess(
            files, port_fanout=len(ports) or 1, identical_fanout=identical)
        rows.append({
            "token": host_token(host, salt),
            "verdict": data["verdict"] or "flagged",
            "signals": [SIGNAL_LABELS.get(k, k) for k in SIGNAL_LABELS if k in data["sig"]],
            "files": safe_rows,
            "shown": len(safe_rows),
            "total": len(files),
            "hidden": max(0, len(files) - len(safe_rows)),
            # True if the server's listing carried ANY size/date. When False, a
            # blank size/date column is honest (a names-only listing), not a gap.
            "has_meta": any(isinstance(e.get("size"), int) or e.get("mtime") for e in files),
            # Potential-honeypot heuristic (curated bait / port fan-out).
            "honeypot": {"flag": True, "reasons": hp_reasons} if hp_flag else None,
        })

    rows.sort(key=lambda r: (_SEV.get(r["verdict"], 9),
                             -sum(1 for f in r["files"] if f.get("alarm")),
                             -r["total"]))
    return rows, len(rows)
