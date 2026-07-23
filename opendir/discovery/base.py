from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Protocol, runtime_checkable

from opendir.models import Candidate
from opendir.discovery.normalize import normalize_url, dedup_key
from opendir.discovery.scope import is_blocked


@dataclass(frozen=True)
class Discovered:
    url: str
    source: str
    source_meta: dict = field(default_factory=dict)


@runtime_checkable
class Source(Protocol):
    name: str
    def fetch(self, since: datetime | None = None) -> Iterable["Discovered"]: ...


def ingest_candidates(source: Source, since: datetime | None = None) -> int:
    created_count = 0
    for d in source.fetch(since):
        if is_blocked(d.url):
            continue
        key = dedup_key(d.url)
        _, created = Candidate.objects.get_or_create(
            dedup_key=key,
            defaults={
                "url": normalize_url(d.url),
                "source": d.source,
                "source_meta": d.source_meta,
            },
        )
        if created:
            created_count += 1
    return created_count
