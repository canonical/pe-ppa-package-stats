# Instruction: PE PPA Package Statistics

Purpose: count the packages published in a set of Launchpad PPAs, **omitting
duplicates** (same source name with different versions/series counted once) and
**omitting kernel-related packages**, then emit a summary table (incl. a kernel
package count + list) and the full package lists into a `.txt` and a `.csv` file.

The implementation is the bundled, self-contained CLI **`pe_ppa_package_stats.py`**
(uses `launchpadlib`; supports public + private PPAs, JSON output, and a
distinct-across-PPAs count). Edit the PPA list (or pass `--ppas`), run the script,
get fresh numbers. See `README.md` for a quick start.

---

## 1. Inputs

A list of PPAs as `owner/archive` pairs (the `~owner` and the
`+archive/ubuntu/<archive>` name from the Launchpad URL).

Default set (built into the script as `DEFAULT_PPAS`; override with `--ppas`):

```
canonical-nvidia/nvidia-desktop-edge
canonical-nvidia/vulkan-packages-nv-desktop
ubuntu-on-renesas/public-ppa
ubuntu-qcom-iot/qcom-ppa
ubuntu-xilinx/default
ubuntu-xilinx/gstreamer
ubuntu-xilinx/sdk
```

Notes on URLs:
- A PPA URL looks like `https://launchpad.net/~OWNER/+archive/ubuntu/ARCHIVE`
  → use `OWNER/ARCHIVE`. The script also accepts full URLs and
  `~owner/ubuntu/archive` reference forms and normalizes them.
- A **bare team URL** like `https://launchpad.net/~ubuntu-xilinx` is **not a PPA**;
  it just hosts PPAs. List that team's archives individually instead. To discover
  a team's archives: `https://api.launchpad.net/devel/~OWNER/ppas`.
- **Private PPAs** are not readable anonymously; they require authenticated
  access — see §8. (The current default set is all public; add private PPAs via
  `--ppas` or `DEFAULT_PPAS`.)

---

## 2. Rules / definitions

1. **Dedupe:** count each `source_package_name` once, regardless of how many
   versions/series it is published in.
2. **Kernel-related (excluded):** source name matching regex
   `^(linux($|-)|flash-kernel($|-))`. This catches `linux`, `linux-*`
   (`linux-meta-*`, `linux-signed-*`, `linux-restricted-*`, `linux-firmware-*`,
   `linux-scripts-*`, `linux-nvidia-*`, `linux-qcom`, …), `flash-kernel`, and
   `flash-kernel-*` (but not an unrelated name such as `flash-kernelish`).
3. **Archived PPAs (skip):** omit any PPA whose archive `displayname` contains
   `(archived)`. NOTE: the API `status` field reports `Active` even for archived
   PPAs, so detection must use the `displayname` substring, not `status`. Override
   with `--include-archived`.
4. **Borderline items kept as non-kernel:** packages that build kernel modules but
   are not part of the `linux*` source family (e.g. `nvidia-graphics-drivers-*`,
   `*-modules` such as `xilinx-vcu-modules`) are **counted** as non-kernel, and
   flagged in a NOTES section so the reviewer can decide. Device firmware not named
   `linux-*` (e.g. `*-firmware`, `firmware-*`) is also kept (the filter targets the
   kernel, not firmware).
5. **TOTAL is additive:** the summary TOTAL sums each PPA's counts, so a package
   published in two PPAs is counted once per PPA. The distinct count across all
   PPAs (each name once) is reported in the NOTES section and via `--global-unique`
   / the JSON `*_distinct_across_ppas` fields.

---

## 3. Data source & method

- Use the **Launchpad API** via `launchpadlib`, not HTML scraping (HTML paginates
  at 75 and is noisy).
- Per PPA the script calls `archive.getPublishedSources(status="Published")`;
  `launchpadlib` follows the `next_collection_link` pagination internally to gather
  **all** publications.
- Archived check per PPA: `archive.displayname` contains `(archived)`.

High-level steps (implemented in `pe_ppa_package_stats.py`):
1. For each PPA, look up the archive (`lp.archives.getByReference`); if its
   `displayname` contains `(archived)` and `--include-archived` is not set, skip.
2. Fetch all published sources (paginated).
3. Reduce to a set of unique `source_package_name`.
4. Split into kernel (regex match) vs non-kernel.
5. Build the summary table (non-kernel count, kernel count, kernel names).
6. Write `pe-ppa-package-counts_YYYYMMDD_HH:MM:SS.txt` (table + kernel lists + full non-kernel lists +
   NOTES — additive-vs-distinct explainer, borderline flags, identical package-set
   detection, skipped PPAs) and `pe-ppa-package-counts_YYYYMMDD_HH:MM:SS.csv` (table only).

---

## 4. Prerequisites

- `python3` (3.8+).
- `launchpadlib` (≥ 1.10):  `pip install -r requirements.txt`
  (preinstalled in this environment as 1.11.0).
- Outbound HTTPS to `launchpad.net` / `api.launchpad.net`.
- For private PPAs: a Launchpad account with read access to the archive (see §8).

---

## 5. The script

The tool is the bundled **`pe_ppa_package_stats.py`** — a single-file,
dependency-light (`launchpadlib` only) CLI, rated 10/10 by pylint and covered by
`test_pe_ppa_package_stats.py` (stdlib `unittest`). It supersedes the earlier
curl-based one-shot prototype.

Key pieces (see the source for detail):
- `KERNEL_RE` / `BORDERLINE_RE` — the classification regexes (§2).
- `DEFAULT_PPAS` — the built-in PPA set (§1); override with `--ppas`.
- `normalize_ppa()` — accepts `owner/archive`, `~owner/archive`,
  `~owner/ubuntu/archive`, or a full PPA URL.
- `login()` — anonymous or cached-OAuth login (§8).
- `analyze()` / `_analyze_one()` — per-PPA fetch, archived/private handling,
  kernel split, borderline flagging.
- `check_ubuntu_availability()` — checks non-kernel package availability against the Ubuntu archive (prefers Launchpad API, falls back to `rmadison` CLI, then web madison API).
- `run_report_phase()` — calculates and prints summary statistics, Ubuntu archive coverage %, per-PPA metrics, and package overlap.
- `build_table()` / `write_csv()` / `write_details_csv()` / `build_txt()` / `build_json()` — rendering.
- `global_unique_counts()` — distinct-across-all-PPAs counts.
- `_exit_code()` — maps skipped PPAs to a process exit code (§6).

Run the unit tests with:

```bash
python3 -m unittest test_pe_ppa_package_stats -v
```

---

## 6. How to run

```bash
# Authenticated (reads private PPAs too). The first run prints a browser
# authorization URL, then caches the token under ~/.cache/pe-ppa-package-stats/:
./pe_ppa_package_stats.py <user>

# Public PPAs only, no auth, custom PPA list:
./pe_ppa_package_stats.py --anonymous --ppas=ubuntu-xilinx/default,ubuntu-xilinx/sdk

# Write the report files to a specific directory:
./pe_ppa_package_stats.py <user> --outdir=/tmp/report

# Also print the distinct-across-all-PPAs count:
./pe_ppa_package_stats.py <user> --global-unique

# Machine-readable output (pure JSON on stdout; files still written unless --no-files):
./pe_ppa_package_stats.py <user> --json > counts.json
```

Options: `--ppas owner/archive,...`, `--anonymous`, `--outdir DIR`, `--no-files`,
`--include-archived`, `--global-unique`, `--json`, `--credentials-file PATH`,
`--service-root ROOT`, `-h/--help`.

Outputs (in `--outdir`, default current directory):
- `pe-ppa-package-details_YYYYMMDD_HH:MM:SS.csv` — single detailed row-per-package table (PPA, package name, type, PPA version, Ubuntu release version, comparison status).
- `pe-ppa-package-counts_YYYYMMDD_HH:MM:SS.txt` — method note, summary table, full package version lists, Ubuntu archive check summary, and NOTES section.

Exit status:
- `0` — success.
- `1` — nothing could be analyzed (no PPAs given, or all lookups failed).
- `2` — finished, but one or more PPAs were skipped/failed for a reason other than
  being archived (e.g. a private PPA queried anonymously). Handy in CI.

---

## 7. Edge cases / lessons learned

- **Pagination:** large PPAs (e.g. qcom-ppa ≈ 100+ publications) span multiple API
  pages; `launchpadlib` follows `next_collection_link` automatically.
- **Multi-series duplicates:** PPAs publishing to several series (Jammy/Noble/
  Questing/Resolute) yield many same-name/different-version rows; dedupe by name.
- **Archived ≠ status:** the API `status` shows `Active` even for archived PPAs;
  rely on `displayname` containing `(archived)`.
- **HTML vs API:** prefer the API; the web `+packages` page truncates at 75 rows
  and is harder to parse reliably.
- **Borderline kernel items:** `nvidia-graphics-drivers-*` and `*-modules`
  (e.g. `xilinx-vcu-modules`) build kernel modules but are kept as non-kernel and
  flagged; move them to the kernel column if a stricter definition is required.
- **Shared packages across PPAs:** some PPAs publish overlapping package sets,
  so the additive TOTAL exceeds the distinct count — use `--global-unique` / the
  JSON `*_distinct_across_ppas` fields for the deduplicated figure.
- **Reference snapshot (captured run):** nvidia-desktop-edge=4(+5k),
  vulkan-packages-nv-desktop=18, public-ppa=7, qcom-ppa=87(+5k), xilinx/default=18(+1k),
  xilinx/gstreamer=15, xilinx/sdk=9(+1k) →
  TOTAL **158** non-kernel, **12** kernel; distinct across all PPAs **153**
  non-kernel, **11** kernel. (xilinx `kria` and `versal` are archived and
  excluded.) Numbers will drift as PPAs change.

---

## 8. Private / authenticated PPAs (OAuth)

Private PPAs require a Launchpad OAuth access token tied to a user who has read
access to the archive (e.g. LP user `<user>`, a member of the owning team).
**The script automates this** — you normally just run `./pe_ppa_package_stats.py <user>`:

1. On the **first** run it creates a request token and prints an authorization URL
   (with `&allow_permission=READ_PRIVATE` for one-click, read-only approval).
2. Log in to launchpad.net as that user, open the URL, click **Authorize** (Read
   Anything, read-only), then press Enter back in the terminal.
3. The access token is exchanged and cached at
   `~/.cache/pe-ppa-package-stats/credentials-<user>.txt` (chmod 600). Subsequent runs
   load it automatically — no re-auth. Override the path with `--credentials-file`.

The script verifies the authenticated identity (`lp.me.name`) and warns if the
token belongs to a different user.

> **Migration note:** the OAuth consumer / cache identity is `pe-ppa-package-stats`
> (matching the script and repo name). If you previously authorized under the old
> `~/.cache/ppa-package-stats/` path, run
> `mv ~/.cache/ppa-package-stats ~/.cache/pe-ppa-package-stats` once to reuse the
> existing token instead of re-authorizing.

Manual two-phase flow (background — this is what the script does internally; useful
for debugging or one-off scripting):

```python
# Phase A — request token + authorization URL (read-only)
from launchpadlib.credentials import Credentials
creds = Credentials("pe-ppa-package-stats (<user>)")       # APP_NAME used by the script
url = creds.get_request_token(web_root="production") + "&allow_permission=READ_PRIVATE"
print(url)        # user opens this & clicks Authorize, then ...

# Phase B — exchange + read (after approval)
from launchpadlib.launchpad import Launchpad
creds.exchange_request_token_for_access_token(web_root="production")
lp = Launchpad(creds, None, None, service_root="production", version="devel",
               cache="~/.cache/pe-ppa-package-stats/http-cache")
arch = lp.archives.getByReference(reference="~OWNER/ubuntu/PRIVATE-ARCHIVE")
names = sorted({p.source_package_name for p in arch.getPublishedSources(status="Published")})
# then apply the same dedupe + KERNEL_RE filter as the public flow
```

Notes:
- `getByReference` takes `~OWNER/ubuntu/ARCHIVE`. `arch.private` confirms privacy.
- The token is stored locally (chmod 600); delete
  `~/.cache/pe-ppa-package-stats/credentials-<user>.txt` to revoke locally, and remove
  the app under launchpad.net → `<user>` → Authorizations to revoke server-side.
