"""Download-safe payload selection.

Picks only files that are SAFE to download and hash: executables and
scripts. Never selects media, archives, documents, or data files, since
those may carry CSAM or PII. This is an intentional allowlist, not a
denylist — unknown extensions are excluded by default.
"""

import re
from urllib.parse import urljoin

PAYLOAD_EXTS = {
    ".exe", ".dll", ".scr", ".msi", ".ps1", ".bat", ".sh", ".vbs", ".hta",
    ".elf", ".bin",
}

WEB_SCRIPT_EXTS = {".php", ".asp", ".aspx", ".jsp"}

WEBSHELL_NAME_RE = re.compile(r"(web)?shell|c99|r57|backdoor|reverse")


def _extension(name: str) -> str:
    dot = name.rfind(".")
    if dot == -1:
        return ""
    return name[dot:]


def _is_payload_name(name: str) -> bool:
    lowered = name.lower()
    ext = _extension(lowered)
    if ext in PAYLOAD_EXTS:
        return True
    if ext in WEB_SCRIPT_EXTS and WEBSHELL_NAME_RE.search(lowered):
        return True
    return False


def select_payload_urls(entries: list[dict], base_url: str, max_files: int = 50) -> list[dict]:
    """Select entries safe to download+hash: allowlisted executables/scripts only.

    Returns a list of {"name", "url"} dicts, capped at max_files. Directories
    are never selected.
    """
    selected = []
    for entry in entries:
        if len(selected) >= max_files:
            break
        if entry.get("is_dir"):
            continue
        name = entry.get("name", "")
        if not _is_payload_name(name):
            continue
        url = urljoin(base_url, entry.get("href") or entry.get("name"))
        selected.append({"name": name, "url": url})
    return selected
