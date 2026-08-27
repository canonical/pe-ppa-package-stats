# TODOs

Deferred work items for `pe-ppa-package-stats`.

## Option 3 — true point-in-time archive versions (Superseded publication history)

Code reference: `pe_ppa_package_stats.py:676` (TODO in `check_ubuntu_availability`),
capture logic in `_check_ubuntu_via_launchpadlib` (`pe_ppa_package_stats.py:498`).

### What the archive lookup captures today

The primary Launchpad query asks for **currently-published** records only:

```
...getPublishedSources&status=Published&source_name=<pkg>
```

So the stored `archive_map` is a single snapshot per package/series:

> "As of scan time, series `noble` has `foo 2.0`, published on `2025-08-01`."

For a historical report (`-r=YYYYMMDD`), the tool uses that one snapshot plus a
date filter: a package counts as "in the archive on date D" only if its
*current* version's `date_published <= D`. Otherwise it collapses to `PPA only`.

### The limitation

Because we only know the currently-published version and its date, we can't see
versions that have since been *superseded*. That makes older historical dates
inaccurate.

Example:
- `foo 2.0` was published in `noble` on `2025-03-01`.
- `foo 3.0` superseded it on `2025-08-01`.
- Today's scan (`status=Published`) sees only `foo 3.0`, dated `2025-08-01`.

Historical report **as of 2025-05-01**:
- The tool sees `foo 3.0` with date `2025-08-01`, which is *after* the target date.
- It concludes `foo` was **not in the archive** on 2025-05-01 -> marks it `PPA only`.
- **Wrong** — `foo 2.0` was actually in the archive that day, and the real
  comparison should have been PPA-vs-`2.0`.

The current model therefore systematically *under-reports* archive presence (and
mis-compares versions) for dates far enough in the past that the archive version
has since changed.

### What Option 3 would do

Query the **full publication history** instead of just the current record — i.e.
include `Superseded` (and `Deleted`) publications, which carry both
`date_published` and `date_superseded`. That gives a per-series timeline:

```
noble: foo 1.0  [2024-11-01 .. 2025-03-01)
       foo 2.0  [2025-03-01 .. 2025-08-01)
       foo 3.0  [2025-08-01 .. now]
```

Then "the version live in series X on date D" is the interval where
`date_published <= D < date_superseded`. That yields **true point-in-time**
archive versions, so historical/quarterly comparisons become exact rather than
"collapses to PPA-only once the snapshot date passes."

### Why it was deferred

- **Cost**: `status=Published` returns ~one record per series; full history
  returns *every* publication ever, per series, per package — much larger
  responses and likely pagination. The current multi-series snapshot is captured
  essentially for free in a single pass.
- **Complexity**: needs interval-matching logic per package/series/date, plus
  handling of deletions and re-uploads.
- **Diminishing value**: the cheap snapshot is accurate for "as of today" and
  recent dates (the common case). The inaccuracy only bites for older historical
  windows where the archive version has since moved — and the tool already prints
  a coverage / missing-dates WARNING so consumers know provenance is limited.

### Rough implementation sketch

1. In `_check_ubuntu_via_launchpadlib`, drop `status=Published` (or query all
   statuses) so the response includes `Superseded`/`Deleted` records.
2. For each package, build a per-series list of
   `{version, date_published, date_superseded}` intervals.
3. Persist those intervals in the `pe-ppa-package-archive_*.json` side-car
   (extends the current `{series: {version, date}}` shape to a timeline).
4. Add an `archive_ver_date_at(archive_map, pkg, series, target_dt)` helper that
   selects the interval containing `target_dt`, and use it from the report
   comparison functions in place of the single-snapshot lookup.
5. Watch out for pagination (`getPublishedSources` is paginated) and the extra
   API/data volume; consider limiting history depth to the reporting window.

## Other open suggestions

Carried over from the original check & verification report (its A/B/D/F/H items
are implemented; E is partly addressed via `.pylintrc`).

- **Disk cache for the Ubuntu-series timeline / `current_series_link`** with a
  TTL (e.g. under `~/.cache/pe-ppa-package-stats/`) so repeat runs avoid network
  calls and `--lastyear`/`--test` work fully offline.
- **Split the single large module** into a small package
  (`cli` / `launchpad` / `ubuntu_archive` / `report` / `io`). The `.pylintrc`
  currently keeps the file at 10/10, but splitting would ease maintenance and
  remove the raised size/complexity limits.
- **CI workflow** (GitHub Actions) running `pyflakes` + `pylint` + `unittest` on
  push; optionally a scheduled scan that appends trend data.
- **Add dev-requirements** (`pyflakes`, `pylint`) alongside `requirements.txt` so
  the lint/test toolchain is pinned and reproducible.
