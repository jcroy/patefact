import time

from django.core.management.base import BaseCommand

from opendir.enrich import virustotal
from opendir.models import PayloadHash


class Command(BaseCommand):
    help = (
        "Look up existing VirusTotal reports (by hash, GET-only -- never "
        "submits/scans a sample) for PayloadHash rows awaiting enrichment."
    )

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--sleep", type=float, default=15)

    def handle(self, *args, **opts):
        pending = list(
            PayloadHash.objects.filter(vt__isnull=True).exclude(sha256="")[: opts["limit"]]
        )

        found = 0
        malicious = 0
        last_index = len(pending) - 1
        for i, payload_hash in enumerate(pending):
            result = virustotal.lookup_hash(payload_hash.sha256)
            payload_hash.vt = result
            payload_hash.save(update_fields=["vt"])

            self.stdout.write(
                f"{payload_hash.sha256[:12]} -> "
                f"found={result.get('found')} malicious={result.get('malicious')}"
            )

            if result.get("found"):
                found += 1
            if (result.get("malicious") or 0) > 0:
                malicious += 1

            if i < last_index:
                time.sleep(opts["sleep"])

        self.stdout.write(
            f"looked up: {len(pending)}, found: {found}, flagged malicious: {malicious}"
        )
