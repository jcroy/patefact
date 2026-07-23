from django.core.management.base import BaseCommand
from opendir.models import Candidate, Snapshot
from opendir.capture.fetcher import Fetcher
from opendir.capture.tier1 import capture_candidate


class Command(BaseCommand):
    help = "Capture pending candidates into snapshots."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--egress", choices=["local", "modal"], default="local",
                            help="Where Tier-1 fetches originate: 'local' (this host's IP) "
                                 "or 'modal' (disposable Modal container, off the local IP).")
        parser.add_argument("--recapture", action="store_true",
                            help="Re-snapshot candidates whose latest snapshot is an open "
                                 "directory (append-only), instead of selecting status='pending'. "
                                 "Use to backfill newly-extracted fields on the existing corpus.")

    def handle(self, *args, **opts):
        if opts["recapture"]:
            open_ids = (
                Snapshot.objects.filter(is_open_dir=True)
                .values_list("candidate_id", flat=True).distinct()
            )
            pending = (
                Candidate.objects.filter(id__in=list(open_ids))
                .order_by("first_seen")[: opts["limit"]]
            )
        else:
            pending = (
                Candidate.objects.filter(status="pending")
                .order_by("first_seen")[: opts["limit"]]
            )
        fetcher = Fetcher(egress=opts["egress"])
        for c in pending:
            try:
                snap = capture_candidate(c, fetcher=fetcher)
                self.stdout.write(f"{c.url} -> {c.status} ({snap.entry_count} entries)")
            except Exception as exc:  # keep an unattended batch alive
                self.stderr.write(f"{c.url} -> FAILED: {exc}")
        self.stdout.write("done")
