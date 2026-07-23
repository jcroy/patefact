# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**patefact** (dir `opendir-observatory`, package `opendir`) is a Django research pipeline that discovers, captures, and classifies publicly exposed **open directories** (`Index of /` autoindex listings) at internet scale. The entire architecture exists to do the dangerous work — fetching and parsing untrusted HTML from live exposures — **off your IP and off your machine**, and to prove nothing sensitive was ever captured. Read the README's "Safety & ethics" section before touching capture/payload/report code.

## Commands

Everything runs through `uv`. Postgres runs in Docker on host port **5544** (not 5432).

```bash
docker compose up -d db                    # Postgres 16 on :5544
uv sync
uv run python manage.py migrate

uv run pytest                              # full suite (~287 tests)
uv run pytest tests/test_rules.py          # one file
uv run pytest tests/test_rules.py -k mirror   # one test by name substring

uv run python scripts/eval_classifier.py   # classifier accuracy vs gold set (pure, no DB)
uv run python scripts/generate_report.py > docs/DEMO_REPORT.md   # aggregate markdown
uv run python scripts/generate_dashboard.py docs/dashboard.html  # redacted HTML dashboard
uv run python manage.py runserver          # Django admin at /admin/ (Unfold-themed)
```

Pipeline management commands (run in order): `discover` → `do_capture` (or `capture`) → `classify` → `hash_payloads` → `vt_lookup`. See each command's module docstring in `opendir/management/commands/` for flags.

Most tests are pure and DB-free thanks to injectable seams (below); tests that touch models need the Postgres container up. `conftest.py` sets `OPENDIR_MIN_INTERVAL=0` so rate-limit sleeps don't slow the suite.

## Safety invariants — do not break these

These are the point of the project. Changes that weaken any of them are almost always wrong:

- **Untrusted HTML is only ever fetched AND parsed off-box.** `capture.tier1.run_capture` *asserts* it is not called with a modal-egress fetcher — parsing runs inside the disposable worker (DO droplet, or Modal container under `capture --egress modal`), never on the operator's host. Only structured/derived data comes back; **raw HTML is never stored** (only its sha256 + structural fingerprints).
- **Download allowlist, not denylist.** `payload/select.py` selects *only* executables/scripts (and web-scripts whose name looks like a webshell). Media, archives, documents, and data files (`.env`, `.sql`, …) are **never downloaded** — only documented from the listing. This is what keeps CSAM/PII out of the system. Do not broaden `PAYLOAD_EXTS`.
- **Hash-and-discard.** Bytes are hashed in the sandbox and thrown away; only hashes land in `PayloadHash`.
- **VirusTotal is lookup-only.** `enrich/virustotal.py` exposes only `lookup_hash` (GET by sha256). Never submit/scan/upload — that would make a sample public.
- **SSRF-safe scoping.** `discovery/scope.is_blocked` rejects private/reserved IPs, numeric-encoding evasions (`0x7f.1`, decimal ints), cloud-metadata, and `.gov/.mil/.internal` suffixes. Redirects are validated hop-by-hop in the fetcher.
- **Two-token DigitalOcean model.** The full `DO_TOKEN` is home-side only. The burner droplet receives *only* a `droplet:delete`-scoped `DO_DELETE_TOKEN`, used solely by its cloud-init self-destruct timer (`infra/cloudinit.py` references nothing but that token + the TTL). The droplet deletes itself on a timer regardless.
- **Reports are aggregate and address-free.** Host identity → a salted-HMAC token (`REPORT_HOST_SALT`), non-reversible. In `scripts/generate_dashboard.py` the redaction gate is load-bearing: executable/script/webshell names are shown (published as threat intel), but data filenames are withheld unless `--full-names`. The `--full-names` output goes to `local/`, which is **gitignored — never commit it** (unredacted, potential PII).

## Architecture

The pipeline is one package per stage; data flows Candidate → Snapshot → Classification/PayloadHash (all **append-only**).

- **`discovery/`** — pluggable sources (`shodan.py`, `censys.py`) behind `base.ingest_candidates`; `normalize.py` produces the `dedup_key`; `scope.py` is the SSRF blocklist. Emits `Candidate` rows.
- **`capture/`** — Tier-1 fetch+parse+fingerprint. `fetcher.Fetcher` (per-host rate limit, redirect validation, byte cap), `parser.parse_autoindex`, `fingerprint.py` (header-order / template / favicon / TLS hashes for clustering), `tier1.run_capture` orchestrates. `modal_app.py` is the optional Modal fallback worker. Emits `Snapshot` rows.
- **`infra/`** — the DigitalOcean disposable-droplet path (primary capture). `orchestrate.run_batch` = provision → deploy → run worker → pull JSONL → ingest → **always teardown**. `provision.py`/`do_client.py` (REST v2, no SDK), `cloudinit.py` (self-destruct user-data), `deploy.py` (ssh/scp/rsync over the operator key), `worker.py` (runs *inside* the droplet; optional thread pool for I/O-bound fan-out), `ingest.py` (JSONL → Snapshots home-side).
- **`classify/`** — deterministic, **versioned** rules engine. `features.extract_features` (pure; `EXTRACTOR_VERSION`) → `rules.classify` (pure; `RULESET_VERSION`; severity-ordered, first match wins) → `service.classify_snapshot` persists a new `Classification`. Labels: `malicious_staging / sensitive_exposure / intentional_public / benign_index`. The full feature vector is stored with every verdict so any classification is reproducible.
- **`payload/`** — `select.select_payload_urls` (the allowlist) → `service.hash_payloads_for_snapshot` (hashes remotely via Modal by default). Emits `PayloadHash`.
- **`enrich/`** — `virustotal.lookup_hash`.
- **`analyze/`** — a **measurement/reporting layer that never changes a verdict** or bumps a version: `inventory.py` (name-based content categories), `file_listing.py` (per-host disclosure policy for reports), `hosts.py`, `ownership.py` (ASN-org network profile), `honeypot.py` (lure/bait detector). Address-free by construction; consumed by the `scripts/` generators.

### Conventions that matter

- **Append-only, versioned.** Reclassifying or recapturing creates a *new* row; nothing is updated in place. The `classify` command dedups by `(snapshot, ruleset_version)` **at the query layer**, not via a DB constraint. When you change feature extraction or rules, bump `EXTRACTOR_VERSION` / `RULESET_VERSION` and run `eval_classifier.py` first.
- **Injectable seams for testability.** Modules that touch network/DO/Modal/subprocess take injectable dependencies (`client`, `transport`, `provision_fn`, `deploy_mod`, `remote_hash`, `sleep`/`monotonic`, module-level `_run`/`_default_*`). Preserve this pattern — it's why the suite runs without hitting any external service. Match it when adding code.
- **Pure core, thin DB shell.** `classify` and `payload` keep pure logic (`features`/`rules`/`select`) separate from a `service.py` that is the only part importing models. Keep new logic pure and push persistence to the service layer.
- **Unfold ordering.** In `config/settings.py`, `unfold` and its contrib apps **must precede** `django.contrib.admin` (first-app-wins template resolution).
