from django.core.management.base import BaseCommand

from opendir.classify.rules import RULESET_VERSION
from opendir.models import Snapshot
from opendir.payload.service import hash_payloads_for_snapshot


class Command(BaseCommand):
    help = (
        "Hash allowlisted payload files (executables/scripts only) for open-directory "
        "snapshots flagged sensitive/malicious at the current ruleset version."
    )

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--labels", type=str, default="sensitive_exposure,malicious_staging")
        parser.add_argument("--max-files", type=int, default=50)

    def handle(self, *args, **opts):
        labels = [label.strip() for label in opts["labels"].split(",") if label.strip()]

        pending = (
            Snapshot.objects.filter(
                is_open_dir=True,
                classifications__ruleset_version=RULESET_VERSION,
                classifications__label__in=labels,
            )
            .exclude(payload_hashes__isnull=False)
            .distinct()
            .select_related("candidate")[: opts["limit"]]
        )

        total = 0
        with_sha256 = 0
        errored = 0
        for snapshot in pending:
            try:
                rows = hash_payloads_for_snapshot(snapshot, max_files=opts["max_files"])
            except Exception as exc:  # keep the batch alive if one dir fails
                self.stderr.write(f"{snapshot.candidate.url}: FAILED: {exc}")
                continue
            self.stdout.write(f"{snapshot.candidate.url}: hashed {len(rows)} payloads")
            for row in rows:
                total += 1
                if row.sha256:
                    with_sha256 += 1
                if row.error:
                    errored += 1

        self.stdout.write(
            f"total payloads hashed: {total}, with sha256: {with_sha256}, errored: {errored}"
        )
