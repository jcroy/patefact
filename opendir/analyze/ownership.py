"""Classify a host's network/hosting profile from its ASN org name.

Heuristic and org-name based (the ``org`` field Shodan already returns per host,
stored in ``Candidate.source_meta``). Buckets each host as cloud (hyperscaler),
hosting/VPS, residential ISP, academic, business, or unknown -- enough to show
*where* exposed open directories actually live (spoiler for this corpus: cloud
and hosting infra, not home connections). No lookups, no network access.
"""
import re
from collections import Counter

# (regex over the org name, category, display provider). First match wins, so
# the specific-provider table is checked before the generic keyword table.
_PROVIDERS = [
    (r"amazon|\baws\b|ec2", "cloud", "Amazon AWS"),
    (r"google", "cloud", "Google Cloud"),
    (r"microsoft|azure", "cloud", "Microsoft Azure"),
    (r"digitalocean", "cloud", "DigitalOcean"),
    (r"\bovh\b", "cloud", "OVH"),
    (r"hetzner", "cloud", "Hetzner"),
    (r"linode|akamai", "cloud", "Linode / Akamai"),
    (r"vultr|choopa", "cloud", "Vultr"),
    (r"oracle", "cloud", "Oracle Cloud"),
    (r"aliyun|alibaba|alicloud", "cloud", "Alibaba Cloud"),
    (r"tencent", "cloud", "Tencent Cloud"),
    (r"softlayer|\bibm\b", "cloud", "IBM / SoftLayer"),
    (r"scaleway|iliad", "cloud", "Scaleway"),
    (r"bisect", "hosting", "BisectHosting"),
    (r"contabo", "hosting", "Contabo"),
    (r"hostpapa", "hosting", "HostPapa"),
    (r"hostwinds", "hosting", "Hostwinds"),
    (r"unified layer|newfold|bluehost|hostgator|endurance", "hosting", "Newfold (Bluehost/HostGator)"),
    (r"leaseweb", "hosting", "Leaseweb"),
    (r"hostinger", "hosting", "Hostinger"),
    (r"godaddy", "hosting", "GoDaddy"),
    (r"namecheap", "hosting", "Namecheap"),
    (r"a100 row|anexia", "hosting", "Anexia"),
]
_PROVIDERS = [(re.compile(p, re.I), cat, disp) for p, cat, disp in _PROVIDERS]

# Generic keyword categories for orgs not in the provider table above.
_CATEGORY_RE = [
    ("academic", re.compile(
        r"univers|academ|research|institut|\bedu\b|college|\.ac\.|(^|\W)icm(\W|$)|science", re.I)),
    ("hosting", re.compile(
        r"host|serv(er|ers|ices)|\bvps\b|dedicat|colocat|data\s?cent|(^|\W)cloud|internet solutions", re.I)),
    ("residential", re.compile(
        r"telecom|broadband|cable|fib(er|re)|communicat|wireless|mobile|\bdsl\b|\bisp\b|"
        r"telefon|vodafone|comcast|verizon|at&t|charter|spectrum|centurylink|telkom|orange|"
        r"deutsche telekom|\bnet\b.*(provider|serv)", re.I)),
]

CATEGORY_DISPLAY = {
    "cloud": "Cloud (hyperscaler)", "hosting": "Hosting / VPS",
    "residential": "Residential ISP", "academic": "Academic / research",
    "business": "Business / other", "unknown": "Unknown",
}
# Fixed display order (most-infrastructure first) for stable charts.
CATEGORY_ORDER = ["cloud", "hosting", "residential", "academic", "business", "unknown"]


def network_profile(org):
    """Return ``(category, provider_display)`` for one ASN org name.

    ``category`` is one of CATEGORY_DISPLAY's keys. ``provider_display`` is a
    tidy provider name for known providers, else the org string itself.
    """
    o = (org or "").strip()
    if not o:
        return "unknown", "Unknown"
    for rx, cat, disp in _PROVIDERS:
        if rx.search(o):
            return cat, disp
    for cat, rx in _CATEGORY_RE:
        if rx.search(o):
            return cat, o
    return "business", o


def profile_breakdown(orgs):
    """Aggregate an iterable of org names into ``(category_counter, provider_counter)``."""
    cats, provs = Counter(), Counter()
    for org in orgs:
        cat, disp = network_profile(org)
        cats[cat] += 1
        provs[disp] += 1
    return cats, provs
