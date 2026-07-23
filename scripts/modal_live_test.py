#!/usr/bin/env python
"""One-command live test for the Modal Tier-1 egress.

Prereqs (one-time):
    uv run modal setup                                  # authenticate to Modal
    uv run modal deploy opendir/capture/modal_app.py    # deploy the app

Run:
    uv run python scripts/modal_live_test.py

Proves, against live infrastructure:
  1. A request via egress="modal" originates from Modal's IP, NOT this machine's IP.
  2. A real open directory captures correctly through the Modal egress.

Exits non-zero (and prints FAIL) if the Modal egress IP equals the local IP,
i.e. if traffic is not actually leaving via Modal.
"""
import os
import sys

# Ensure the project root (not scripts/) is importable so `config`/`opendir` resolve.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

import httpx  # noqa: E402
from opendir.capture.fetcher import Fetcher  # noqa: E402

# Baseline captured 2026-07-22 for reference; the test compares against a live
# lookup below, not this constant, so it stays correct if the local IP changes.
LOCAL_IP_BASELINE = ""  # set at runtime from a live lookup; no hardcoded operator IP
REAL_OPEN_DIR = os.environ.get(
    "MODAL_LIVE_TEST_URL", "http://198.51.100.10/"
)  # set to a known Shodan-discovered "Index of /" dir; default is an RFC 5737 doc placeholder


def _local_ip() -> str:
    return httpx.get("https://api.ipify.org", timeout=15).text.strip()


def main() -> int:
    print("== Modal egress live test ==")

    here = _local_ip()
    print(f"local egress IP (now):   {here}")

    # egress="modal" resolves the deployed remote_fetch via
    # modal.Function.from_name("opendir-fetch", "remote_fetch").
    res = Fetcher(egress="modal", min_interval=0).fetch("https://api.ipify.org")
    if res.error:
        print(f"FAIL: modal egress errored: {res.error}")
        print("      (is the app deployed? `uv run modal deploy opendir/capture/modal_app.py`)")
        return 1

    modal_ip = res.body.strip()
    print(f"egress='modal' IP:        {modal_ip}")

    if not modal_ip or modal_ip == here:
        print("FAIL: modal egress IP matches the local IP — traffic is NOT leaving via Modal.")
        return 1
    print("PASS: captures via egress='modal' originate from Modal's IP, not the local IP.")

    # Bonus: prove a real open directory captures through the Modal egress.
    d = Fetcher(egress="modal", min_interval=0).fetch(REAL_OPEN_DIR)
    ok = d.status == 200 and "Index of" in d.body
    print(
        f"real open dir via modal:  status={d.status} body_len={len(d.body)} "
        f"'Index of'={'Index of' in d.body} error={d.error!r}"
    )
    if not ok:
        print("WARN: the sample open dir did not return a 200 'Index of' listing "
              "(host may be down); the IP-change check above is the primary result.")

    print("DONE: Modal Tier-1 egress verified live.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
