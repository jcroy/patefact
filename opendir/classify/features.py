"""Deterministic feature extraction for open-directory classification.

Pure functions only, no DB access: given a Snapshot's ``listing_entries``
(a list of ``{name, href, is_dir, size, mtime, path}`` dicts), produce a
deterministic feature dict suitable for downstream classification.
"""

import re

EXTRACTOR_VERSION = "1.1.0"

SENSITIVE_PATTERNS = {
    "env":        [r"(^|/)\.env(\.|$)"],
    "git":        [r"(^|/)\.git(/|$)"],
    "sql_dump":   [r"\.sql(\.gz|\.zip|\.bz2)?$", r"dump.*\.sql"],
    "backup":     [r"backup", r"\.bak$", r"\.old$"],
    "ssh_key":    [r"id_rsa", r"id_dsa", r"id_ed25519", r"authorized_keys"],
    "priv_key":   [r"\.pem$", r"\.key$", r"\.ppk$", r"\.pfx$"],
    "config":     [r"wp-config", r"config\.(php|json|ya?ml|ini)$", r"\.htpasswd$", r"\.htaccess$"],
    "credential": [r"credential", r"password", r"secret", r"\.kdbx$"],
    "database":   [r"\.sqlite\d?$", r"\.db$", r"\.mdb$"],
    "capture":    [r"\.pcap$"],
    "vpn":        [r"\.ovpn$"],
}
PAYLOAD_PATTERNS = {
    # A webshell is a WEB SCRIPT (.php/.asp/.jsp/...) named like a shell/backdoor
    # -- NOT any name containing "shell" (which false-matches Xshell.exe,
    # PowerShell, a dir called "shell", etc.). Requiring the web-script extension
    # is what keeps a benign software mirror from reading as malicious staging.
    "webshell":     [r"(?:(?:web)?shell|\bc99\b|\br57\b|backdoor|reverse[_-]?shell)"
                     r"[^/]*\.(?:php\d?|phtml|phar|asp|aspx|jsp|jspx|cfm)$"],
    "executable":   [r"\.exe$", r"\.dll$", r"\.scr$", r"\.msi$"],
    "script":       [r"\.ps1$", r"\.bat$", r"\.sh$", r"\.vbs$", r"\.hta$"],
    "malware_tool": [r"mimikatz", r"cobalt", r"meterpreter", r"beacon", r"lazagne", r"njrat"],
    "binary":       [r"\.elf$", r"\.bin$"],
}
# Distribution artifacts (installers, archives, media). A directory dominated by
# these is a mirror -- so an installer download mirror (many .exe) routes to
# intentional_public, not sensitive/malicious, once no webshell/tool/secret is
# present. .exe stays in the executable payload category too (recorded for
# transparency); mirror-dominance is what changes the verdict, not the ext alone.
MIRROR_EXTS = {
    ".zip", ".7z", ".rar", ".xz", ".bz2", ".iso", ".tgz", ".gz", ".tar",
    ".deb", ".rpm", ".whl", ".jar", ".msi", ".exe", ".dmg", ".pkg", ".appimage",
    ".mp4", ".mkv", ".pdf",
}
_EXT_RE = re.compile(r"(\.[a-z0-9]{1,6})$")


def _compile_patterns(patterns: dict[str, list[str]]) -> dict[str, list[re.Pattern]]:
    return {
        category: [re.compile(p, re.IGNORECASE) for p in regexes]
        for category, regexes in patterns.items()
    }


_SENSITIVE_RE = _compile_patterns(SENSITIVE_PATTERNS)
_PAYLOAD_RE = _compile_patterns(PAYLOAD_PATTERNS)


def extract_features(entries: list[dict], *, server_kind: str = "", tls: dict | None = None) -> dict:
    """Extract a deterministic feature dict from a Snapshot's listing_entries.

    Pure function: same input always produces the same output. No DB access.
    """
    entry_count = 0
    file_count = 0
    dir_count = 0
    sensitive_hits: dict[str, int] = {category: 0 for category in _SENSITIVE_RE}
    payload_hits: dict[str, int] = {category: 0 for category in _PAYLOAD_RE}
    mirror_files = 0
    ext_counts: dict[str, int] = {}

    for entry in entries:
        entry_count += 1
        name = str(entry.get("name", ""))
        lowered = name.lower()

        # Sensitive/payload patterns apply to ALL entries, dirs included, so an
        # exposed .git/ / .svn/ / backup/ directory is detected (these are the
        # highest-value signals and normally appear as directory entries).
        for category, regexes in _SENSITIVE_RE.items():
            if any(r.search(lowered) for r in regexes):
                sensitive_hits[category] += 1

        for category, regexes in _PAYLOAD_RE.items():
            if any(r.search(lowered) for r in regexes):
                payload_hits[category] += 1

        if bool(entry.get("is_dir")):
            dir_count += 1
            continue

        file_count += 1
        m = _EXT_RE.search(lowered)
        if m:
            ext = m.group(1)
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            if ext in MIRROR_EXTS:
                mirror_files += 1

    top_exts = dict(
        sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    )

    return {
        "entry_count": entry_count,
        "file_count": file_count,
        "dir_count": dir_count,
        "sensitive_hits": sensitive_hits,
        "payload_hits": payload_hits,
        "mirror_files": mirror_files,
        "mirror_ratio": mirror_files / max(file_count, 1),
        "top_exts": top_exts,
        "server_kind": server_kind,
        "cert_self_signed": bool(tls.get("self_signed")) if tls else False,
    }
