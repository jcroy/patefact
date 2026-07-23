# patefact — Demo Report

_Generated 2026-07-23. Aggregate figures only — individual host addresses and operators are withheld, since these are live real-world exposures._

## Pipeline

Shodan discovery → capture via a **disposable, self-destructing cloud worker** (a DigitalOcean droplet; requests never originate from the operator's IP) → autoindex validation → deterministic rules-first classification. Untrusted HTML is parsed and fingerprinted **on the disposable worker**; only structured, derived data returns.

## Corpus

- **Candidates discovered** (Shodan): 7127
- **Captured**: 6422
- **Validated open directories**: 5640
- **False-positive rate**: 11% of pages that matched Shodan's `Index of /` title were actually normal websites (stale matches) — caught and excluded by title/`<h1>` validation.

## Network profile

Where the exposed hosts actually live, by their ASN owner (from Shodan — no extra lookups). Open directories cluster on **cloud & hosting infrastructure**, not home connections:

| Network type | Hosts | Share |
|---|---:|---:|
| Cloud (hyperscaler) | 1614 | 31% |
| Hosting / VPS | 1074 | 21% |
| Residential ISP | 453 | 9% |
| Academic / research | 133 | 3% |
| Business / other | 1921 | 37% |
| Unknown | 32 | 1% |

**Top providers**: Amazon AWS (419), DigitalOcean (245), Tencent Cloud (218), Hetzner (205), Newfold (Bluehost/HostGator) (175), OVH (162), Contabo (125), BisectHosting (85)

**Top countries**: US (1293), DE (690), CN (577), RU (431), BR (417), IN (192), FR (128), SG (128), HK (124), GB (122)

## Classification

Rules-first classifier (ruleset `v1.1.0`), 5640 dirs:

| Label | Count | Share |
|---|---:|---:|
| `malicious_staging` | 23 | 0% |
| `sensitive_exposure` | 1766 | 31% |
| `intentional_public` | 197 | 3% |
| `benign_index` | 3654 | 65% |

## What was exposed (aggregate signal prevalence)

Number of open directories in which each signal appeared:

| Signal | Dirs |
|---|---:|
| backups | 808 |
| SQL dumps | 599 |
| config files | 568 |
| exposed .git repos | 168 |
| .env files | 149 |
| credential files | 121 |
| private keys | 78 |
| VPN configs | 55 |
| database files | 53 |
| SSH keys | 10 |
| packet captures | 9 |
| ⚠️ scripts (.ps1/.bat/.sh) | 414 |
| ⚠️ executables (.exe/.dll) | 291 |
| ⚠️ raw binaries | 48 |
| ⚠️ webshells/backdoors | 12 |
| ⚠️ known offensive tools | 11 |

## File types

Most common file extensions, by number of directories containing them:

| Ext | Dirs |
|---|---:|
| `.php` | 1240 |
| `.html` | 976 |
| `.txt` | 882 |
| `.json` | 745 |
| `.zip` | 638 |
| `.sql` | 527 |
| `.md` | 522 |
| `.ico` | 437 |
| `.js` | 430 |
| `.lock` | 396 |
| `.xml` | 382 |
| `.gz` | 351 |

## Server software

apache: 4065, python: 837, nginx: 738

## Deeper inventory mining (name-based)

Heuristic characterization from **filenames only** — no content is ever accessed, so a match means the *name suggests* that content. Number of open directories containing at least one match:

| Category | Dirs |
|---|---:|
| log files | 388 |
| financial data (invoices/bank/payroll) | 285 |
| VCS / source-control dirs | 196 |
| personal records (customers/employees/passwords) | 142 |
| cloud credentials (aws/kube/tfstate) | 72 |
| auth secrets / tokens / keystores | 64 |

- **Exposed volume**: 2761 dirs report file sizes — ~6.7 TB of listed files, 5178 single files over 100 MB.

## Per-host file inventory (anonymized)

Concrete file-level evidence per **pseudonymous host** — a salted-HMAC token, stable but non-reversible (a bare hash of an IP would be trivially reversible). **Executable and script files are shown by name** (a program name isn't PII), with content hashes where we hashed them; a **⚠ marks confirmed webshells or VirusTotal-flagged files**. **Every other file shows only its type, size, and date** — filenames are withheld because a data filename can itself be PII. Worst 20 of 1445 flagged hosts:


_**4** of these hosts are flagged as **potential honeypots** — bait listings (a curated set of high-value files, or a byte-identical listing fanned across many ports) that mimic a leak to trap scanners. Marked ⚠ below._

#### `host-447fbb` — malicious — 22 files
_Signals: ⚠ webshell_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `FxCodeShell.jsp` | — | — | — |
| ⚠ `FxCodeShell.jsp` | — | — | — |
| `.md` | — | — | — |
| `.jsp::$data` | — | — | — |
| `.md` | — | — | — |
| `.txt` | — | — | — |
| `.bash_history` | — | — | — |
| `.bash_logout` | — | — | — |
| `.bashrc` | — | — | — |
| `.profile` | — | — | — |
| _+12 more files_ | | | |

#### `host-489d6b` — malicious — 5 files
_Signals: ⚠ webshell_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `breeze_shell.php` | 147 B | 2026-05-25T18:04 | — |
| ⚠ `breeze_shell5.php` | 147 B | 2026-05-25T18:04 | — |
| `.php` | 24.0 KB | 2026-04-18T15:33 | — |
| `.php` | 2.0 KB | 2025-11-06T16:50 | — |
| `.phtml` | 147 B | 2026-05-25T18:04 | — |

#### `host-a4c683` — malicious — 442 files
_Signals: ⚠ webshell · private keys · credential files · personal-records files · auth secrets/tokens · config files · executables · scripts · raw binaries · backups · packet captures · log files_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.py` | — | — | — |
| `.py` | — | — | — |
| `.py` | — | — | — |
| `.txt` | — | — | — |
| `.log` | — | — | — |
| `.json` | — | — | — |
| `.log` | — | — | — |
| _+432 more files_ | | | |

#### `host-f42666` — malicious — 285 files
_Signals: ⚠ webshell · private keys · SSH keys · config files · executables · scripts · raw binaries · packet captures · log files_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `include_shell.jsp` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| _+275 more files_ | | | |

#### `host-59ddb0` — malicious — 43 files
_Signals: ⚠ webshell · SQL dumps · config files · executables_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | 339 B | 2026-07-21T13:56 | — |
| `fwd.exe` | 6.0 KB | 2026-07-21T15:05 | — |
| `.zip` | 471.0 MB | 2022-12-14T10:18 | — |
| `.zip` | 59.0 MB | 2022-12-19T09:11 | — |
| `.dit` | 50.0 MB | 2026-07-21T19:11 | — |
| `.sql` | 17.0 MB | 2022-10-19T09:53 | — |
| `.b64` | 15.0 MB | 2026-07-21T17:02 | — |
| `(no ext)` | 12.0 MB | 2026-07-21T06:32 | — |
| `.save` | 11.0 MB | 2026-07-21T17:01 | — |
| `.ico` | 198.0 KB | 2010-12-31T08:10 | — |
| _+33 more files_ | | | |

#### `host-f19749` — malicious — 43 files
_Signals: ⚠ webshell · SQL dumps · config files · executables_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | 339 B | 2026-07-21T13:56 | — |
| `fwd.exe` | 6.0 KB | 2026-07-21T15:05 | — |
| `.zip` | 471.0 MB | 2022-12-14T10:18 | — |
| `.zip` | 59.0 MB | 2022-12-19T09:11 | — |
| `.dit` | 50.0 MB | 2026-07-21T19:11 | — |
| `.sql` | 17.0 MB | 2022-10-19T09:53 | — |
| `.b64` | 15.0 MB | 2026-07-21T17:02 | — |
| `(no ext)` | 12.0 MB | 2026-07-21T06:32 | — |
| `.save` | 11.0 MB | 2026-07-21T17:01 | — |
| `.ico` | 198.0 KB | 2010-12-31T08:10 | — |
| _+33 more files_ | | | |

#### `host-77f100` — malicious — 43 files
_Signals: ⚠ webshell · SQL dumps · config files · executables_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | 339 B | 2026-07-21T13:56 | — |
| `fwd.exe` | 6.0 KB | 2026-07-21T15:05 | — |
| `.zip` | 471.0 MB | 2022-12-14T10:18 | — |
| `.zip` | 59.0 MB | 2022-12-19T09:11 | — |
| `.dit` | 50.0 MB | 2026-07-21T19:11 | — |
| `.sql` | 17.0 MB | 2022-10-19T09:53 | — |
| `.b64` | 15.0 MB | 2026-07-21T17:02 | — |
| `(no ext)` | 12.0 MB | 2026-07-21T06:32 | — |
| `.save` | 11.0 MB | 2026-07-21T17:01 | — |
| `.ico` | 198.0 KB | 2010-12-31T08:10 | — |
| _+33 more files_ | | | |

#### `host-67252d` — malicious — 43 files
_Signals: ⚠ webshell · SQL dumps · config files · executables_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | 339 B | 2026-07-21T13:56 | — |
| `fwd.exe` | 6.0 KB | 2026-07-21T15:05 | — |
| `.zip` | 471.0 MB | 2022-12-14T10:18 | — |
| `.zip` | 59.0 MB | 2022-12-19T09:11 | — |
| `.dit` | 50.0 MB | 2026-07-21T19:11 | — |
| `.sql` | 17.0 MB | 2022-10-19T09:53 | — |
| `.b64` | 15.0 MB | 2026-07-21T17:02 | — |
| `(no ext)` | 12.0 MB | 2026-07-21T06:32 | — |
| `.save` | 11.0 MB | 2026-07-21T17:01 | — |
| `.ico` | 198.0 KB | 2010-12-31T08:10 | — |
| _+33 more files_ | | | |

#### `host-7b519f` — malicious — 19 files
_Signals: ⚠ webshell · config files · backups_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | 510 B | 2026-06-07T07:36 | — |
| `.php` | 44.4 KB | 2021-08-18T13:32 | — |
| `.php` | 31.0 KB | 2021-08-18T13:32 | — |
| `.php` | 21.8 KB | 2026-05-12T05:52 | — |
| `.php` | 8.3 KB | 2021-08-18T13:32 | — |
| `.php` | 7.7 KB | 2026-05-13T07:02 | — |
| `.bak` | 7.6 KB | 2026-06-07T06:29 | — |
| `.php` | 7.6 KB | 2026-06-07T06:51 | — |
| `.php` | 7.6 KB | 2026-06-07T06:29 | — |
| `.php` | 7.0 KB | 2021-08-18T13:32 | — |
| _+9 more files_ | | | |

#### `host-22362e` — malicious — 15 files
_Signals: ⚠ webshell · SQL dumps · log files_

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | 473 B | 2026-04-02T20:24 | `sha256:e3b0c44298fc…` · VT: clean |
| `.log` | 5.5 KB | 2024-03-01T05:38 | — |
| `.sql` | 343.0 MB | 2024-03-01T05:38 | — |
| `.lock` | 187.0 KB | 2023-09-06T07:04 | — |
| `.php` | 43.0 KB | 2026-07-12T21:46 | — |
| `.php` | 28.0 KB | 2026-05-22T21:16 | — |
| `.json` | 2.2 KB | 2023-09-06T07:04 | — |
| `.md` | 1.9 KB | 2022-06-24T05:41 | — |
| `(no ext)` | 1.6 KB | 2022-06-24T05:41 | — |
| `.xml` | 899 B | 2022-06-24T05:41 | — |
| _+5 more files_ | | | |

#### `host-4add54` — malicious — 15 files
_Signals: ⚠ webshell · .git repo · source-control dirs_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | — | — | — |
| `.c` | — | — | — |
| `(no ext)` | — | — | — |
| `.c` | — | — | — |
| `(no ext)` | — | — | — |
| `.c` | — | — | — |
| `.php` | — | — | — |
| `(no ext)` | — | — | — |
| `.c` | — | — | — |
| `.txt` | — | — | — |
| _+5 more files_ | | | |

#### `host-5a3e93` — malicious — 1 files
_Signals: ⚠ webshell_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| ⚠ `shell.php` | — | — | — |

#### `host-21f3f0` — malicious — 13849 files
_Signals: ⚠ offensive tooling · credential files · SQL dumps · personal-records files · config files · executables · scripts · backups_

| File | Size | Modified | Hash |
|---|---:|---|---|
| `.php` | 22.0 KB | 2026-04-30T06:31 | — |
| `.php` | 14.0 KB | 2026-04-30T06:31 | — |
| `.php` | 14.0 KB | 2026-04-30T06:31 | — |
| `.php` | 14.0 KB | 2026-04-30T06:31 | — |
| `.php` | 11.0 KB | 2026-04-30T06:31 | — |
| `.php` | 3.4 KB | 2026-04-30T06:31 | — |
| `.scss` | 2.0 KB | 2026-04-30T06:30 | — |
| `.less` | 1.9 KB | 2026-04-30T06:30 | — |
| `.js` | 1.8 KB | 2026-04-30T06:30 | — |
| `.php` | 1.6 KB | 2026-04-30T06:31 | — |
| _+13839 more files_ | | | |

#### `host-53f512` — malicious — 307 files
_Signals: ⚠ offensive tooling · SQL dumps · auth secrets/tokens · executables · scripts · log files_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| `.log` | — | — | — |
| `.txt` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| `.log` | — | — | — |
| _+297 more files_ | | | |

#### `host-b66073` — malicious — 270 files
_Signals: ⚠ offensive tooling · credential files · auth secrets/tokens · config files · log files_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| `.yml` | — | — | — |
| `.gitattributes` | — | — | — |
| `.gitignore` | — | — | — |
| `.mailmap` | — | — | — |
| `.yml` | — | — | — |
| `(no ext)` | — | — | — |
| `.md` | — | — | — |
| `.md` | — | — | — |
| `.md` | — | — | — |
| `.json` | — | — | — |
| _+260 more files_ | | | |

#### `host-6bedb2` — malicious — 63 files
_Signals: ⚠ offensive tooling · credential files · personal-records files · executables · scripts · raw binaries · backups_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| `(no ext)` | — | — | — |
| `8443.exe` | — | — | — |
| `ADExplorer.exe` | — | — | — |
| `ADExplorer64.exe` | — | — | — |
| `ADExplorer64a.exe` | — | — | — |
| `FreeTools.exe` | — | — | — |
| `INQUISITIVE_SHOW-STOPPER.bin` | — | — | — |
| `meterpreter.ps1` | — | — | — |
| `newchess.exe` | — | — | — |
| `Payload.exe` | — | — | — |
| _+53 more files_ | | | |

#### `host-ca28bf` — malicious — 54 files
_Signals: ⚠ offensive tooling · auth secrets/tokens · scripts · backups · VPN configs · log files_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| `.log` | — | — | — |
| `.log` | — | — | — |
| `launch_nuclei_bulk.sh` | — | — | — |
| `launch_nuclei_seq.sh` | — | — | — |
| `nuclei_fofa_monitor.sh` | — | — | — |
| `nuclei_monitor.sh` | — | — | — |
| `openvpn.sh` | — | — | — |
| `.bash_history` | — | — | — |
| `.bashrc` | — | — | — |
| `.json` | — | — | — |
| _+44 more files_ | | | |

#### `host-004a77` — malicious — 20 files
_Signals: ⚠ offensive tooling · config files_

| File | Size | Modified | Hash |
|---|---:|---|---|
| `.sorry` | 53.0 KB | 2026-04-30T16:37 | — |
| `.sorry` | 36.0 KB | 2026-04-30T16:37 | — |
| `.sorry` | 33.0 KB | 2026-04-30T16:37 | — |
| `.sorry` | 22.0 KB | 2026-04-30T16:34 | — |
| `.sorry` | 11.0 KB | 2026-04-30T16:37 | — |
| `.>` | 10.0 KB | 2026-04-30T16:36 | — |
| `.sorry` | 9.5 KB | 2026-04-30T16:36 | — |
| `.sorry` | 9.5 KB | 2026-04-30T16:36 | — |
| `.sorry` | 7.8 KB | 2026-04-30T16:37 | — |
| `.sorry` | 7.4 KB | 2026-04-30T16:37 | — |
| _+10 more files_ | | | |

#### `host-e6caba` — malicious — 17 files
_Signals: ⚠ offensive tooling · executables · scripts_

_Names-only listing — this server publishes no file sizes or dates._

| File | Size | Modified | Hash |
|---|---:|---|---|
| `b.exe` | — | — | — |
| `beacon2.ps1` | — | — | — |
| `collect.bat` | — | — | — |
| `collect2.bat` | — | — | — |
| `copy_sam.bat` | — | — | — |
| `copyhiv.bat` | — | — | — |
| `cs.exe` | — | — | — |
| `dump.bat` | — | — | — |
| `hb.exe` | — | — | — |
| `listener.ps1` | — | — | — |
| _+7 more files_ | | | |

#### `host-616751` — malicious — 10 files
_Signals: ⚠ offensive tooling_

| File | Size | Modified | Hash |
|---|---:|---|---|
| `.ini-bak-3-20-2018` | 28.0 KB | 2018-03-20T15:31 | — |
| `.html` | 4.8 KB | 2018-05-24T14:04 | — |
| `.ico` | 4.2 KB | 2018-05-24T14:04 | — |
| `.htm` | 3.8 KB | 2018-05-24T14:04 | — |
| `.shtml` | 251 B | 2018-05-24T14:04 | — |
| `.>` | 248 B | 2017-10-05T18:27 | — |
| `.>` | 53 B | 2017-08-30T14:05 | — |
| `.txt` | 31 B | 2018-05-24T14:04 | — |
| `.html` | 28 B | 2015-10-29T12:02 | — |
| `.php` | 21 B | 2018-05-24T14:04 | — |

_…and 1425 more flagged hosts (full inventory in the local DB only; addresses and data-file names are never published)._

## Payload analysis

For directories flagged sensitive/malicious, an allowlist of **executable/script files only** (never media, archives, documents, or data files) is downloaded, hashed, and **discarded on the disposable worker** — only the hash is kept. Sensitive-data files (`.env`, `.sql`, …) are documented from the listing and **never downloaded**.

- **Payloads hashed** (SHA-256 + TLSH, hash-and-discard): 16  ·  6 skipped (over size cap / unreachable)
- **Types hashed**: `.sh`×9, `.bat`×3, `.exe`×2, `.php`×1, `.ps1`×1
- **VirusTotal (lookup-by-hash, never submitted)**: 7 known to VT, **0 flagged malicious**
  - The recognized payloads are legitimate software/config scripts, not malware — consistent with the corpus being *exposures/misconfigurations* rather than active malware staging.

## Notable patterns

- **Targeted discovery works**: queries like `http.html:".env"` / `".sql"` surfaced directories with a far higher sensitive-content rate than a generic `Index of /` sweep (which is dominated by benign software/media mirrors).
- **Infrastructure clustering**: a single staging host was observed across ~12 different ports serving byte-identical SQL-dump listings — the kind of one-host, many-ports fan-out that graph-based infrastructure analysis (planned P3) surfaces.
- **Validation matters**: a meaningful fraction of Shodan `Index of /` matches were stale — the host now serves an ordinary website — and were correctly rejected before classification.

## Reproducibility

Deterministic throughout: feature extractor `v1.1.0`, ruleset `v1.1.0`. Every classification stores its full feature vector plus both version stamps, so any verdict can be reproduced or re-run under a new ruleset.

