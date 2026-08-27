# pe-ppa-package-stats

Count the source packages published across a set of Launchpad PPAs — collapsing
duplicate versions/series, excluding kernel-related packages, skipping archived
PPAs, and (optionally) reading **private** PPAs via authenticated access.

It prints a summary table and writes report files:

- `pe-ppa-package-details_YYYYMMDD_HH:MM:SS.csv` — single detailed row-per-package CSV (PPA, package name, type, PPA version, Ubuntu release version, comparison status).
- `pe-ppa-package-counts_YYYYMMDD_HH:MM:SS.txt` — summary table + full package version lists + notes.
- `pe-ppa-package-meta_YYYYMMDD_HH:MM:SS.json` — metadata side-car (provenance/quality).
- `pe-ppa-package-archive_YYYYMMDD_HH:MM:SS.json` — multi-series archive snapshot (only when the primary Launchpad API path captured it; see below).

## Features

- Dedupes by source package name (versions/series counted once).
- Excludes kernel packages (`^(linux($|-)|flash-kernel($|-))`); keeps and flags
  borderline kernel-module builders (e.g. `nvidia-graphics-drivers-*`, `*-modules`).
- Skips archived PPAs (detected via `displayname`, not the misleading `status`).
- Reads private PPAs through cached Launchpad OAuth (read-only).
- `--global-unique` and JSON output report the **distinct** package count across
  all PPAs (the table TOTAL is additive and double-counts shared packages).
- `--json` for machine-readable output; meaningful exit codes for CI.

## How it works

The tool runs up to two phases — a **GATHERING** (scan) phase and a
**REPORTING** phase — selected by the CLI flags (`-s/--scan`, `-r/--report`,
`-a/--all`; with no phase flag it runs both):

```text
                 $ ./pe_ppa_package_stats.py [flags]
                                |
                                v
                        +----------------+
                        |   parse_args   |
                        +----------------+
                                |
                  decide which phases to run from the flags:
             -s/--scan    -r/--report    -a/--all    (no flag = both)
                                |
        run_scan? ----yes-------+
                                |
                                v
   +===================================================================+
   |  GATHERING PHASE  (scan)                                          |
   +===================================================================+
                                |
                 --test ?  --yes-->  load newest local *_details.csv
                                |     (reuse a prior scan, no network)
                                no
                                v
                 login( --anonymous | cached Launchpad OAuth )
                                |
                                v
                 analyze PPAs
                   - dedupe by source-package name
                   - split kernel vs non-kernel
                   - skip archived / no-access PPAs
                                |
                                v
                 check Ubuntu archive availability  (per package)
                   1) Launchpad REST API  -> version + publish date
                        (also captures the multi-series archive_map)
                   2) rmadison CLI        -> version only  (fallback)
                   3) web madison API     -> version only  (fallback)
                                |
                                v
                 write timestamped outputs to --outdir:
                   *_details.csv     *_counts.txt
                   *_meta.json       *_archive.json  (only if API captured)
                                |
        run_report? ---yes------+
                                |
                                v
   +===================================================================+
   |  REPORTING PHASE  (report)                                        |
   +===================================================================+
                                |
                                v
                 load newest local *_details.csv
                        + newest *_archive.json (if present)
                                |
                                v
                 pick mode:
                   -r                    -> status as of today
                   -r=YYYYMMDD           -> historical (auto dev series)
                   --lastyear            -> last 4 quarters trend
                   --last-n-quarters N   -> last N quarters trend
                                |
                                v
                 compare PPA vs Ubuntu archive, per source package:
                   PPA older | PPA same | PPA newer | PPA only
                 dedupe by name; per-PPA + distinct totals; date coverage
                                |
                                v
                 emit report:  formatted text   (or --json)
                                |
                                v
          exit code: 0 = ok | 1 = nothing analyzed | 2 = some PPAs skipped
```

## Ubuntu archive lookups & historical accuracy

Package availability in the Ubuntu archive is checked in three tiers:

1. **Launchpad REST API** (primary) — resilient (per-package retries; a single
   slow request never aborts the batch). Returns version **and publication
   date**, which is what enables accurate historical / quarterly reporting.
2. **`rmadison` CLI** (fallback) — version + availability only, **no dates**.
3. **web madison API** (fallback) — version + availability only, **no dates**.

The fallbacks are fine for the default "status as of today" report, but they do
**not** provide archive publication dates. If the primary path succeeds for most
packages but a few individual queries fail, only those are re-queried via the
fallbacks and merged in, so the dates for the rest are preserved. If a scan
falls back entirely, historical (`-r=YYYYMMDD`) and quarterly (`--lastyear`)
reports cannot confirm when a package entered the archive, so archive-present
packages collapse into `PPA only`; the tool then prints a clear **WARNING** and
you should re-run a scan (primary API) to capture the dates.

Every scan also writes a small **metadata side-car**
(`pe-ppa-package-meta_*.json`) recording the tool version, the Ubuntu series,
which tier produced the data (`ubuntu_source`), package totals, and the
arrival-date coverage — so report consumers can judge data provenance/quality.

When the primary Launchpad API path is used, the scan additionally writes an
**archive side-car** (`pe-ppa-package-archive_*.json`) capturing, at no extra
cost, each package's version and publication date **for every Ubuntu series**
(not just the one scanned). Historical (`-r=YYYYMMDD`) and quarterly reports
load the latest archive side-car and compare each package against its own
development series when that series is covered. If a requested report series is
**not** covered by the snapshot (e.g. an older CSV scanned only one series), the
report falls back to the scanned-series columns as an approximation and prints a
clear **series-mismatch NOTE**; the quarterly table's `Source` column marks each
quarter as `archive` (exact) or `csv-approx` (approximated) accordingly.

## Requirements

- Python 3.8+
- [`launchpadlib`](https://launchpad.net/launchpadlib) ≥ 1.10

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Authenticated (also reads private PPAs). First run prints an authorization URL,
# then caches the token under ~/.cache/pe-ppa-package-stats/ for subsequent runs:
./pe_ppa_package_stats.py <user>

# Public PPAs only, no auth, custom PPA list:
./pe_ppa_package_stats.py --anonymous --ppas=ubuntu-xilinx/default,ubuntu-xilinx/sdk

# Write report files to a specific directory:
./pe_ppa_package_stats.py <user> --outdir=/tmp/report

# Print the distinct-across-all-PPAs count as well:
./pe_ppa_package_stats.py <user> --global-unique

# Machine-readable JSON on stdout (files still written unless --no-files):
./pe_ppa_package_stats.py <user> --json > counts.json
```

### Options

| Option | Description |
| --- | --- |
| `-s`, `--scan` | Run scan phase: query PPAs and write timestamped data files. |
| `-r [YYYYMMDD]`, `--report[=YYYYMMDD]` | Run report phase: print statistics as of today, or historical status as of `YYYYMMDD` (e.g. `-r=20260101`); automatically uses the Ubuntu release in development on that date unless `--ubuntu-series` is specified. |
| `--lastyear`, `--last-year` | Quarterly report comparing the last 4 consecutive quarters (shorthand for `--last-n-quarters 4`). |
| `--last-n-quarters N` | Quarterly report comparing the last `N` consecutive quarters. |
| `-a`, `--all` | Run scan phase followed by report phase (default behavior). |
| `-t`, `--test` | Test mode: reuse latest local CSV scan data instead of querying Launchpad. |
| `LP_USER` | Launchpad user to authenticate as (required unless `--anonymous` or `--report`). |
| `--ppas owner/archive,...` | Comma-separated PPAs to analyze (overrides the default set). Accepts `owner/archive` or full PPA URLs. |
| `--anonymous` | Query anonymously (public PPAs only; private ones are skipped). |
| `--outdir DIR` | Directory for the output files (default: current directory). |
| `--no-files` | Only print to stdout; do not write the csv/txt files. |
| `--include-archived` | Also include PPAs whose display name says `(archived)`. |
| `--ubuntu-series SERIES` | Ubuntu release series to check package availability against (default: automatically determined for the report date, e.g. `stonking`, `resolute`, `plucky`, `noble`). |
| `--no-ubuntu-check` | Skip checking package availability in the Ubuntu archive. |
| `--global-unique` | Also print the count of packages unique across ALL PPAs. |
| `--json` | Emit machine-readable JSON to stdout instead of tables (works for the scan phase and for report/historical/quarterly reports). |
| `--credentials-file PATH` | Where to cache/load the OAuth token. |
| `--service-root ROOT` | Launchpad service root (default: `production`). |
| `-h`, `--help` | Show help and exit. |

If `--ppas` is omitted, a built-in default set is used (see `DEFAULT_PPAS` in the
script, documented in `instruction_PE-PPA-stats.md` §1).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Nothing could be analyzed (no PPAs, or all lookups failed). |
| `2` | Finished, but one or more PPAs were skipped/failed for a reason other than being archived (e.g. a private PPA queried anonymously). |

## Private PPAs (authentication)

Private PPAs need a Launchpad OAuth token tied to a user with read access. The
script automates the two-phase OAuth flow on first use and caches the token at
`~/.cache/pe-ppa-package-stats/credentials-<user>.txt` (chmod 600); later runs reuse
it without prompting. See `instruction_PE-PPA-stats.md` §8 for details and the
manual flow.

## Development

```bash
pip install -r dev-requirements.txt                # pyflakes + pylint (pinned)
python3 -m unittest test_pe_ppa_package_stats -v   # run the tests
python3 -m pyflakes pe_ppa_package_stats.py test_pe_ppa_package_stats.py
python3 -m pylint pe_ppa_package_stats.py test_pe_ppa_package_stats.py
```

The tests use small fakes in place of `launchpadlib`, so they need no network
access. Both the script and the tests are kept at pylint 10/10 (via the
committed `.pylintrc`, which formalizes the agreed style exceptions — long
help/report literals and deliberate lazy imports — and sets design limits that
match the single-file CLI's shape).

## Files

| File | Purpose |
| --- | --- |
| `pe_ppa_package_stats.py` | The CLI tool. |
| `test_pe_ppa_package_stats.py` | Unit tests (stdlib `unittest`). |
| `.pylintrc` | Pylint configuration keeping both files at 10/10. |
| `requirements.txt` | Runtime dependency pin. |
| `dev-requirements.txt` | Lint/test toolchain pins (pyflakes, pylint). |
| `instruction_PE-PPA-stats.md` | Full runbook (rules, method, edge cases, OAuth). |
| `TODOs.md` | Deferred work items (e.g. point-in-time archive history). |
| `LICENSE` | GNU GPL v3.0. |
| `README.md` | This file. |

> The generated `pe-ppa-package-details_*.csv` / `pe-ppa-package-counts_*.txt` are report
> output and are intentionally git-ignored.

## License

This project is licensed under the **GNU General Public License v3.0** — see the
[`LICENSE`](LICENSE) file for the full text.
