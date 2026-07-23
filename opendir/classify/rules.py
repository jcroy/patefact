"""Rules-first classifier for open-directory feature dicts.

Pure function, no DB access: given the feature dict produced by
``opendir.classify.features.extract_features``, produce a deterministic
classification decision. Rules are severity-ordered and the first match
wins (most dangerous signal takes precedence over weaker/benign ones).
"""

from opendir.classify.features import EXTRACTOR_VERSION

RULESET_VERSION = "1.1.0"

# Categories in opendir.classify.features.PAYLOAD_PATTERNS that indicate an
# active malicious-staging area (attacker tooling / webshells) rather than
# merely "some executable/script exists".
_MALICIOUS_PAYLOAD_CATEGORIES = ("webshell", "malware_tool", "executable", "script")

# Categories in opendir.classify.features.SENSITIVE_PATTERNS that indicate a
# credential/config/data leak worth flagging on their own (order used for
# reasons list; confidence still sums ALL sensitive_hits values, including
# categories not in this trigger list, e.g. backup/capture/vpn).
_SENSITIVE_TRIGGER_CATEGORIES = (
    "env", "git", "ssh_key", "priv_key", "sql_dump", "credential", "config", "database",
)


def _confidence(base: float, hits: float, cap: float = 0.95) -> float:
    return min(base + 0.1 * hits, cap)


def classify(features: dict) -> dict:
    """Classify a feature dict into a label with confidence and reasons.

    Rules are evaluated in severity order; the first matching rule wins:
      1. malicious_staging  - webshell/malware_tool payload present
      2. sensitive_exposure - env/git/ssh_key/priv_key/sql_dump/credential/config/database present
      3. sensitive_exposure - loose executables/scripts NOT in a mirror context
      4. intentional_public - mirror-like directory (installer/archive/media heavy)
      5. benign_index        - default: no notable signal

    Rule 3 is guarded by ``mirror_ratio``: a directory dominated by distribution
    artifacts (a software-installer mirror) is NOT flagged sensitive just for
    containing executables -- it falls through to rule 4 (intentional_public).
    Confirmed attacker tooling (rule 1) and credential/data leaks (rule 2) are
    checked first, so a mirror that actually hides a webshell or .env still wins.
    """
    sensitive_hits: dict = features.get("sensitive_hits", {}) or {}
    payload_hits: dict = features.get("payload_hits", {}) or {}
    mirror_ratio = features.get("mirror_ratio", 0.0) or 0.0
    file_count = features.get("file_count", 0) or 0

    extractor_version = features.get("extractor_version") or EXTRACTOR_VERSION

    webshell = payload_hits.get("webshell", 0)
    malware_tool = payload_hits.get("malware_tool", 0)
    executable = payload_hits.get("executable", 0)
    script = payload_hits.get("script", 0)

    label: str
    confidence: float
    reasons: list[str]

    # 1. malicious_staging: webshell or malware_tool present.
    if webshell >= 1 or malware_tool >= 1:
        label = "malicious_staging"
        confidence = _confidence(0.6, webshell + malware_tool + executable + script)
        reasons = [
            category
            for category in _MALICIOUS_PAYLOAD_CATEGORIES
            if payload_hits.get(category, 0) >= 1
        ]

    # 2. sensitive_exposure: strong sensitive category present.
    elif any(sensitive_hits.get(category, 0) >= 1 for category in _SENSITIVE_TRIGGER_CATEGORIES):
        label = "sensitive_exposure"
        confidence = _confidence(0.6, sum(sensitive_hits.values()))
        reasons = [
            category
            for category in _SENSITIVE_TRIGGER_CATEGORIES
            if sensitive_hits.get(category, 0) >= 1
        ]

    # 3. sensitive_exposure (weaker): loose executables/scripts, but NOT when the
    #    directory is mirror-dominated (a software-installer/archive mirror falls
    #    through to intentional_public instead of being flagged for its .exe's).
    elif any(count >= 1 for count in payload_hits.values()) and mirror_ratio < 0.6:
        label = "sensitive_exposure"
        confidence = 0.5
        reasons = ["executable/script content without mirror context"]

    # 4. intentional_public: predominantly archive/media (mirror-like).
    elif mirror_ratio >= 0.6 and file_count >= 3:
        label = "intentional_public"
        confidence = 0.7
        reasons = ["predominantly archive/media files (mirror-like)"]

    # 5. benign_index: default, no notable signal.
    else:
        label = "benign_index"
        confidence = 0.5
        reasons = ["open directory with no notable signals"]

    return {
        "label": label,
        "confidence": confidence,
        "reasons": reasons,
        "extractor_version": extractor_version,
        "ruleset_version": RULESET_VERSION,
    }
