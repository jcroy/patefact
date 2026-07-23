from collections import Counter

from django.core.management.base import BaseCommand

from opendir.classify.rules import RULESET_VERSION
from opendir.classify.service import classify_snapshot
from opendir.models import Snapshot


class Command(BaseCommand):
    help = "Classify open-directory snapshots that lack a classification at the current ruleset version."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=200)

    def handle(self, *args, **opts):
        pending = (
            Snapshot.objects.filter(is_open_dir=True)
            .exclude(classifications__ruleset_version=RULESET_VERSION)
            .select_related("candidate")
            .order_by("fetched_at")[: opts["limit"]]
        )
        label_counts = Counter()
        for snapshot in pending:
            try:
                classification = classify_snapshot(snapshot)
            except Exception as exc:  # keep an unattended batch alive
                self.stderr.write(f"{snapshot.candidate.url} -> FAILED: {exc}")
                continue
            label_counts[classification.label] += 1
            self.stdout.write(
                f"{snapshot.candidate.url} -> {classification.label} ({classification.confidence:.2f})"
            )
        self.stdout.write("label distribution: " + ", ".join(
            f"{label}={count}" for label, count in label_counts.most_common()
        ))
