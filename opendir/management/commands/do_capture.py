"""Capture candidates on a disposable DigitalOcean droplet (off-IP, off-box).

    manage.py do_capture --recapture --limit 50          # backfill open dirs
    manage.py do_capture --smoke                          # provision->ssh->destroy only
    manage.py do_capture --limit 20 --keep                # leave the box up to debug

Env (from .env): DO_TOKEN (full, home only), DO_DELETE_TOKEN (droplet:delete
only), DO_SSH_KEY_FINGERPRINT, DO_SSH_KEY_PATH, optional DO_REGION / DO_SIZE.
"""
import os
from datetime import datetime, timezone as _tz

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from opendir.infra.provision import DropletConfig, provision, teardown
from opendir.infra import deploy
from opendir.infra.orchestrate import run_batch, select_candidate_urls

IMAGE = "ubuntu-24-04-x64"


class Command(BaseCommand):
    help = "Capture candidates on a disposable DigitalOcean droplet."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--recapture", action="store_true",
                            help="Re-capture open dirs (backfill) instead of status='pending'.")
        parser.add_argument("--ttl-minutes", type=int, default=45)
        parser.add_argument("--region", default=os.environ.get("DO_REGION", "nyc3"))
        parser.add_argument("--size", default=os.environ.get("DO_SIZE", "s-1vcpu-1gb"))
        parser.add_argument("--keep", action="store_true", help="Skip destroy (debug).")
        parser.add_argument("--smoke", action="store_true",
                            help="Provision, verify SSH, then destroy. No capture.")
        parser.add_argument("--concurrency", type=int, default=1,
                            help="Concurrent fetches inside the droplet worker "
                                 "(I/O-bound; ~10-15 is a good bulk value). Default 1 = serial.")
        parser.add_argument("--fetch-timeout", type=float, default=None,
                            help="Per-request fetch timeout on the droplet (default 20s); "
                                 "lower (e.g. 8) to trim the dead-host tail on big runs.")

    def _cfg(self, opts):
        if not os.environ.get("DO_TOKEN"):
            raise CommandError("DO_TOKEN not set (full-access token; home-side only).")
        delete_token = os.environ.get("DO_DELETE_TOKEN", "")
        fp = os.environ.get("DO_SSH_KEY_FINGERPRINT", "")
        if not delete_token:
            raise CommandError("DO_DELETE_TOKEN not set (scope a droplet:delete-only token).")
        if not fp:
            raise CommandError("DO_SSH_KEY_FINGERPRINT not set.")
        stamp = datetime.now(_tz.utc).strftime("%Y%m%d-%H%M%S")
        return DropletConfig(
            name=f"patefact-{stamp}", region=opts["region"], size=opts["size"],
            image=IMAGE, ssh_key_fingerprints=[fp], delete_token=delete_token,
            ttl_minutes=opts["ttl_minutes"],
        )

    def handle(self, *args, **opts):
        cfg = self._cfg(opts)

        if opts["smoke"]:
            handle = provision(cfg)
            self.stdout.write(f"SSH OK -> root@{handle.ip} (droplet {handle.id}); destroying")
            teardown(handle)
            self.stdout.write("smoke OK")
            return

        urls = select_candidate_urls(opts["recapture"], opts["limit"])
        if not urls:
            self.stdout.write("no candidates selected")
            return
        repo_dir = str(settings.BASE_DIR)
        results_dir = os.path.join(str(settings.BASE_DIR), ".do_runs")
        os.makedirs(results_dir, exist_ok=True)
        results_path = os.path.join(results_dir, "do_results.jsonl")
        contact = getattr(settings, "OPENDIR_CONTACT", "")
        self.stdout.write(f"capturing {len(urls)} urls on a disposable droplet…")
        if opts["keep"]:
            self.stdout.write(self.style.WARNING(
                f"--keep: home-side teardown skipped, but cloud-init STILL self-destructs "
                f"this droplet in ~{opts['ttl_minutes']} min. Pass --ttl-minutes to keep it longer."))

        stats = run_batch(cfg, urls, repo_dir, results_path,
                          keep=opts["keep"], contact=contact,
                          concurrency=opts["concurrency"], fetch_timeout=opts["fetch_timeout"])
        self.stdout.write(
            f"done: {stats.snapshots} snapshots, {stats.errors} errors, "
            f"{stats.unmatched} unmatched"
        )
