"""Deeper, name-based characterization of an open directory's inventory.

This is a *measurement* layer that sits beside the versioned classifier
(``opendir.classify``): it does NOT change any verdict or bump the extractor/
ruleset version. It mines the file/dir *names* we already hold -- no fetching,
no content access -- for categories the classifier's verdict signals don't
cover (personal records, financial data, cloud credentials, auth secrets,
VCS/source leaks, logs), and derives size-based severity from the listing's
size column once it is populated.

Everything here is heuristic and *name-based*: a match means the filename
*suggests* that content, not that the content was inspected. Aggregate reports
should present counts only -- individual filenames can themselves be PII.
"""
import re

# Data-file extensions used to anchor PII/financial hints to actual data
# exports (a ``customers.csv`` dump), not framework code dirs (``users/``).
_DATA_EXT = r"\.(csv|xlsx?|sql|json|xml|txt|dat|db|sqlite\d?|bak|dump|zip|gz|tar|7z|rar|pdf)$"

INTEREST_PATTERNS = {
    "personal_records": [
        rf"(?:^|[^a-z])(customers?|clients?|employees?|members?|contacts?|patients?|"
        rf"students?|users?|payroll|personal|profiles?)[^/]*{_DATA_EXT}",
        r"\bpasswd\b", r"\bpasswords?\b", r"(^|[-_ ])ssn([-_. ]|$)",
        r"passport", r"national.?id", r"\bkyc\b", r"resume|(^|[-_ ])cv\.",
        r"medical|health.?record",
    ],
    "financial": [
        rf"(?:^|[^a-z])(invoices?|receipts?|transactions?|payments?|payroll|salar(?:y|ies)|"
        rf"accounts?|ledger|billing|bank|statements?)[^/]*{_DATA_EXT}",
        r"credit.?card", r"\bcardholder\b", r"wallet\.dat", r"\biban\b",
    ],
    "cloud_creds": [
        r"(^|/)\.aws(/|$)", r"(^|/)credentials$", r"\.npmrc", r"\.pypirc",
        r"\.dockercfg", r"docker[-_]?config\.json", r"service.?account.*\.json",
        r"client_secret.*\.json", r"(^|/)\.?kube(config)?", r"\.tfstate$",
        r"(^|/)\.netrc$", r"gcloud", r"azure.*\.json",
    ],
    "auth_secrets": [
        r"(^|[-_./ ])api[-_]?keys?([-_. ]|$)", r"(^|[-_./ ])tokens?([-_. ]|$)",
        r"\.jks$", r"\.p12$", r"\.pfx$", r"keystore", r"\.kdbx$",
        r"\.gpg$", r"(^|/)secrets?\.(ya?ml|json|txt|env)$", r"(^|[-_.])jwt([-_.]|$)",
    ],
    "vcs_source": [
        r"(^|/)\.svn(/|$)", r"(^|/)\.hg(/|$)", r"(^|/)\.bzr(/|$)",
        r"\.ds_store$", r"thumbs\.db$", r"(^|/)\.idea(/|$)", r"(^|/)\.vscode(/|$)",
        r"(^|/)\.git(/|$)",
    ],
    "logs": [
        r"\.log$", r"access[-_.]?log", r"error[-_.]?log", r"debug[-_.]?log",
    ],
}
_COMPILED = {cat: [re.compile(p, re.I) for p in pats] for cat, pats in INTEREST_PATTERNS.items()}

_BIG_FILE_BYTES = 100 * 1024 * 1024  # 100 MB -> a "large exposed file"


def scan_names(entries, *, max_examples: int = 5) -> dict:
    """Return ``{category: {count, examples}}`` for name-suggested content.

    ``examples`` is capped and intended for local triage; aggregate/public
    reporting should use ``count`` only (filenames can be PII).
    """
    result: dict[str, dict] = {}
    for e in entries:
        name = str(e.get("name", ""))
        low = name.lower()
        for cat, regexes in _COMPILED.items():
            if any(r.search(low) for r in regexes):
                bucket = result.setdefault(cat, {"count": 0, "examples": []})
                bucket["count"] += 1
                if len(bucket["examples"]) < max_examples:
                    bucket["examples"].append(name)
    return result


def size_stats(entries) -> dict:
    """Size-based severity from the listing's size column (files only).

    All-``None`` sizes (e.g. a listing that omits the size column, or a
    pre-backfill snapshot) yield ``has_sizes=False`` and zeroed totals.
    """
    sized = [(e.get("size"), str(e.get("name", ""))) for e in entries if not e.get("is_dir")]
    known = [(s, n) for s, n in sized if isinstance(s, int)]
    total = sum(s for s, _ in known)
    largest = max(known, default=(0, ""))
    return {
        "has_sizes": bool(known),
        "file_count": len(sized),
        "total_bytes": total,
        "largest_bytes": largest[0],
        "largest_name": largest[1],
        "files_over_100mb": sum(1 for s, _ in known if s >= _BIG_FILE_BYTES),
    }


def analyze(entries) -> dict:
    """Full name+size characterization of one listing's entries."""
    return {"interest": scan_names(entries), "size": size_stats(entries)}
