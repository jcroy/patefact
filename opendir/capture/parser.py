import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit
from selectolax.parser import HTMLParser


@dataclass
class Entry:
    name: str
    href: str
    is_dir: bool
    size: int | None
    mtime: str | None
    path: str


@dataclass
class ListingResult:
    server_kind: str
    entries: list[Entry]
    title: str
    is_open_dir: bool


_PARENT = {"../", "..", "parent directory"}
_LISTING_SIGNATURE = re.compile(r"^\s*(index of |directory listing for )", re.I)

# Trailing "<date> <size>" metadata on a <pre>-listing line, after the anchor.
_NGINX_TAIL = re.compile(r"(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2})\s+(\d+|-)")
_APACHE_TAIL = re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+(\S+)")
_SIZE_RE = re.compile(r"^([\d.]+)\s*([KMGTP]?)(i?B)?$", re.I)
_DATE_HINT = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}-[A-Za-z]{3}-\d{4}")
_SIZE_HINT = re.compile(r"^([\d.]+\s*[KMGTP]?i?B?|-)$", re.I)
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
_SIZE_EXP = {"": 0, "K": 1, "M": 2, "G": 3, "T": 4, "P": 5}


def _parse_size(text: str) -> int | None:
    """Human-readable ("2.5K", "4.0M") or raw-byte ("2560") size -> int bytes.

    Apache uses 1024-based units; nginx emits raw bytes. "-"/blank -> None.
    """
    s = (text or "").strip()
    if not s or s == "-":
        return None
    m = _SIZE_RE.match(s)
    if not m:
        return None
    try:
        num = float(m.group(1))
    except ValueError:
        return None
    return int(round(num * (1024 ** _SIZE_EXP.get(m.group(2).upper(), 0))))


def _parse_mtime(text: str) -> str | None:
    """Normalise a listing timestamp to ``YYYY-MM-DDTHH:MM`` (locale-safe).

    Handles nginx ``DD-Mon-YYYY HH:MM`` and Apache ``YYYY-MM-DD HH:MM``. An
    unrecognised but non-empty value is returned verbatim; "-"/blank -> None.
    """
    s = (text or "").strip()
    if not s or s == "-":
        return None
    m = re.match(r"(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2})", s)  # nginx
    if m:
        day, mon, year, hh, mm = m.groups()
        month = _MONTHS.get(mon.lower())
        if month:
            return f"{year}-{month:02d}-{day}T{hh}:{mm}"
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})", s)  # apache iso
    if m:
        year, month, day, hh, mm = m.groups()
        return f"{year}-{month}-{day}T{hh}:{mm}"
    return s


def _entry_meta(a) -> tuple[int | None, str | None]:
    """Best-effort (size, mtime) for one anchor, from its table row or pre line.

    Never raises: untrusted markup that doesn't match a known layout yields
    (None, None) rather than breaking the whole capture.
    """
    try:
        # Table layout (Apache HTMLTable): metadata lives in sibling <td>s.
        row, node, hops = None, a.parent, 0
        while node is not None and hops < 4:
            if node.tag == "tr":
                row = node
                break
            node = node.parent
            hops += 1
        if row is not None:
            size = mtime = None
            for td in row.css("td"):
                if td.css_first("a") is not None:
                    continue  # skip the name cell (holds the anchor)
                cell = td.text().strip()
                if mtime is None and _DATE_HINT.search(cell):
                    mtime = _parse_mtime(cell)
                elif size is None and _SIZE_HINT.match(cell):
                    size = _parse_size(cell)
            return size, mtime

        # Pre layout (nginx / Apache default): metadata trails the anchor text.
        nxt = a.next
        tail = nxt.text() if (nxt is not None and nxt.tag == "-text") else ""
        line = tail.split("\n", 1)[0]
        m = _NGINX_TAIL.search(line) or _APACHE_TAIL.search(line)
        if m:
            return _parse_size(m.group(2)), _parse_mtime(m.group(1))
    except Exception:
        pass
    return None, None


def _server_kind(html: str, tree) -> str:
    low = html.lower()
    if "directory listing for" in low:                 # Python http.server
        return "python"
    has_sort_links = any(
        (a.attributes.get("href") or "").lower().startswith("?c=") for a in tree.css("a")
    )
    has_icons = any(
        "/icons/" in (img.attributes.get("src") or "").lower() for img in tree.css("img")
    )
    if has_sort_links or has_icons:                    # Apache mod_autoindex markers, in real markup
        return "apache"
    if "index of" in low and "<pre" in low:             # bare pre listing without Apache markup -> nginx
        return "nginx"
    if "index of" in low:                               # table-style or other Apache-ish listing
        return "apache"
    return "unknown"


def parse_autoindex(html: str, base_url: str) -> ListingResult:
    tree = HTMLParser(html)
    entries: list[Entry] = []
    for a in tree.css("a"):
        href = a.attributes.get("href") or ""
        name = (a.text() or href).strip()
        if not href or href.startswith(("?", "#")):
            continue
        if name.lower() in _PARENT or href in ("../", ".."):
            continue
        is_dir = href.endswith("/")
        abs_url = urljoin(base_url, href)
        path = urlsplit(abs_url).path
        size, mtime = _entry_meta(a)
        entries.append(Entry(name=name, href=href, is_dir=is_dir,
                             size=size, mtime=mtime, path=path))

    t = tree.css_first("title")
    title = t.text().strip() if t else ""
    is_open_dir = bool(_LISTING_SIGNATURE.match(title)) or any(
        _LISTING_SIGNATURE.match(h.text() or "") for h in tree.css("h1")
    )
    return ListingResult(server_kind=_server_kind(html, tree), entries=entries,
                         title=title, is_open_dir=is_open_dir)
