"""Ingest a droplet worker's results.jsonl into Snapshots (home-side).

Reuses the shared ingest_capture_dict so a JSONL record produces exactly the
same Snapshot a local or Modal capture would.
"""
import json
from dataclasses import dataclass

from opendir.models import Candidate
from opendir.capture.tier1 import ingest_capture_dict


@dataclass
class IngestStats:
    snapshots: int = 0
    errors: int = 0
    unmatched: int = 0
    malformed: int = 0


def ingest_jsonl(path) -> IngestStats:
    stats = IngestStats()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url")
                candidate = Candidate.objects.filter(url=url).first() if url else None
                if candidate is None:
                    stats.unmatched += 1
                    continue
                snap = ingest_capture_dict(candidate, data)
            except (json.JSONDecodeError, KeyError):
                stats.malformed += 1
                continue
            if snap.error:
                stats.errors += 1
            else:
                stats.snapshots += 1
    return stats
