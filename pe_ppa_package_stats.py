#!/usr/bin/env python3
"""
pe_ppa_package_stats.py - count source packages across Launchpad PPAs.

For each PPA it counts the UNIQUE source packages, collapsing duplicate
versions/series, EXCLUDING kernel-related packages (names matching "linux*" or
"flash-kernel*"), SKIPPING archived PPAs, and supporting PRIVATE PPAs through
authenticated (OAuth) access as a given Launchpad user.

It prints summary tables and (by default) writes timestamped files per scan:
  - pe-ppa-package-details_YYYYMMDD_HH:MM:SS.csv : detailed row-per-package CSV
  - pe-ppa-package-meta_YYYYMMDD_HH:MM:SS.json   : scan metadata (source tier, coverage, version)
  - pe-ppa-package-archive_YYYYMMDD_HH:MM:SS.json: multi-series archive snapshot
                                                   (only when the primary API captured it)
  - pe-ppa-package-counts_YYYYMMDD_HH:MM:SS.txt  : full text report + per-PPA package lists

Examples:
  ./pe_ppa_package_stats.py <user>
  ./pe_ppa_package_stats.py --anonymous -a
  ./pe_ppa_package_stats.py --anonymous -s                   # scan phase only
  ./pe_ppa_package_stats.py -r                               # report phase (status as of today)
  ./pe_ppa_package_stats.py -r=20260101                      # historical report (status as of 2026-01-01)
  ./pe_ppa_package_stats.py --lastyear                       # last 4 quarters trend
  ./pe_ppa_package_stats.py --last-n-quarters 8              # last 8 quarters trend
  ./pe_ppa_package_stats.py -r=20260101 --json               # historical report as JSON
  ./pe_ppa_package_stats.py -t -r                            # test mode: report using local CSV

Exit status: 0 = success, 1 = nothing could be analyzed, 2 = finished but one
or more PPAs were skipped/failed (other than being archived).

Requires: python3 and launchpadlib  (pip install -r requirements.txt)
"""
# Help text and report literals are intentionally kept on single lines for
# readability, so line-too-long is accepted here (the one agreed exception).
# pylint: disable=line-too-long
import argparse
from collections import namedtuple
import concurrent.futures
import csv
from datetime import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

try:
    from launchpadlib.launchpad import Launchpad
    from launchpadlib.credentials import Credentials
except ImportError as _exc:  # pragma: no cover - only hit without the dependency
    raise SystemExit(
        "ERROR: launchpadlib is not installed. "
        "Install it with:  pip install launchpadlib"
    ) from _exc

# --- The PPAs we used, as the built-in default set (override with --ppas) -----
DEFAULT_PPAS = [
    "canonical-nvidia/nvidia-desktop-edge",
    "canonical-nvidia/vulkan-packages-nv-desktop",
    "ubuntu-on-renesas/public-ppa",
    "ubuntu-qcom-iot/qcom-ppa",
    "ubuntu-xilinx/default",
    "ubuntu-xilinx/gstreamer",
    "ubuntu-xilinx/sdk",
]

KERNEL_RE = re.compile(r'^(linux($|-)|flash-kernel($|-))')
BORDERLINE_RE = re.compile(r'(-modules$|^nvidia-graphics-drivers)')

APP_NAME = "pe-ppa-package-stats"
TOOL_VERSION = "0.1"
CSV_DETAILS_NAME = "pe-ppa-package-details_{timestamp}.csv"
META_NAME = "pe-ppa-package-meta_{timestamp}.json"
ARCHIVE_NAME = "pe-ppa-package-archive_{timestamp}.json"
TXT_NAME = "pe-ppa-package-counts_{timestamp}.txt"

# Cohesive carrier for Ubuntu-availability data passed into the report phase:
#   info        - per-package availability dict (in-memory scans; None for CSV)
#   archive     - multi-series archive snapshot {pkg: {series: {version, date}}}
#   series_seen - list of series captured in the archive snapshot
#   scan_series - the development series active when the scan ran
UbuntuData = namedtuple("UbuntuData", ["info", "archive", "series_seen", "scan_series"])
UbuntuData.__new__.__defaults__ = (None, None, (), None)


def get_output_filenames(now=None):
    """Return (csv_details, meta_json, archive_json, txt) filenames (timestamped)."""
    if now is None:
        now = datetime.now()
    ts = now.strftime("%Y%m%d_%H:%M:%S")
    return (
        CSV_DETAILS_NAME.format(timestamp=ts),
        META_NAME.format(timestamp=ts),
        ARCHIVE_NAME.format(timestamp=ts),
        TXT_NAME.format(timestamp=ts),
    )

EXIT_OK = 0
EXIT_NO_RESULTS = 1
EXIT_PARTIAL = 2


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args(argv):
    """Parse the command-line arguments in *argv* and return the namespace."""
    epilog = "Default PPAs (used when --ppas is not given):\n  " + \
             "\n  ".join(DEFAULT_PPAS)
    p = argparse.ArgumentParser(
        prog="pe_ppa_package_stats.py",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
        epilog=epilog,
    )
    p.add_argument("-h", "--help", "-?", action="help",
                   help="show this help message and exit")
    p.add_argument("lp_user", nargs="?", metavar="LP_USER",
                   help="Launchpad user to authenticate as (required to read "
                        "private PPAs). Omit only together with --anonymous.")
    p.add_argument("--ppas", metavar="owner/archive,...",
                   help="comma-separated list of PPAs to analyze, overriding the "
                        "default set. Accepts 'owner/archive' or full "
                        "launchpad.net PPA URLs.")
    p.add_argument("--anonymous", action="store_true",
                   help="query anonymously (public PPAs only; private skipped)")
    p.add_argument("--outdir", default=".", metavar="DIR",
                   help="directory for the output files (default: current dir)")
    p.add_argument("--no-files", action="store_true",
                   help="only print the table; do not write the csv/txt files")
    p.add_argument("--global-unique", action="store_true",
                   help="also print the count of packages unique across ALL PPAs "
                        "(the TOTAL row is additive and double-counts shared packages)")
    p.add_argument("--json", action="store_true",
                   help="print results as a JSON document to stdout instead of the "
                        "table (csv/txt files are still written unless --no-files)")
    p.add_argument("--include-archived", action="store_true",
                   help="also include PPAs whose display name says '(archived)'")
    p.add_argument("--ubuntu-series", default=None, metavar="SERIES",
                   help="Ubuntu release series to check package availability against "
                        "(default: automatically determined for the report date)")
    p.add_argument("--no-ubuntu-check", action="store_true",
                   help="skip checking package availability in the Ubuntu archive")
    p.add_argument("-s", "-S", "--scan", action="store_true",
                   help="run scan phase: query PPAs and write timestamped data files")
    p.add_argument("-r", "-R", "--report", nargs="?", const="today", metavar="YYYYMMDD",
                   help="run report phase: calculate and print statistics as of today, "
                        "or as of target date YYYYMMDD (e.g. -r=20260101); automatically "
                        "uses the Ubuntu release in active development on that date "
                        "unless --ubuntu-series is specified")
    p.add_argument("-a", "-A", "--all", action="store_true",
                   help="run scan phase followed by report phase (default behavior)")
    p.add_argument("--lastyear", "--last-year", action="store_true",
                   help="run quarterly reporting for the last 4 consecutive quarters "
                        "(shorthand for --last-n-quarters 4)")
    p.add_argument("--last-n-quarters", type=int, default=None, metavar="N",
                   help="run quarterly reporting for the last N consecutive quarters")
    p.add_argument("-t", "--test", action="store_true",
                   help="test mode: reuse local scan CSV data instead of querying Launchpad")
    p.add_argument("--credentials-file", metavar="PATH",
                   help="where to cache/load the OAuth token (default: "
                        "~/.cache/pe-ppa-package-stats/credentials-<user>.txt)")
    p.add_argument("--service-root", default="production", metavar="ROOT",
                   help="Launchpad service root (default: production)")
    args = p.parse_args(argv)

    if args.report and str(args.report).lower() in ("lastyear", "last-year"):
        args.lastyear = True

    if args.last_n_quarters is not None and args.last_n_quarters < 1:
        p.error("--last-n-quarters must be >= 1")
    if args.last_n_quarters is not None:
        args.lastyear = True

    # Effective number of quarters for the quarterly report (default 4).
    args.quarters_n = args.last_n_quarters if args.last_n_quarters is not None else 4

    if args.lastyear and not args.report:
        args.report = "lastyear"

    if not args.scan and not args.report and not args.all:
        args.all = True
        args.report = "today"

    if (args.scan or args.all) and not args.test and not args.anonymous and not args.lp_user:
        p.error("provide LP_USER (a Launchpad username) or use --anonymous")
    if args.anonymous and args.lp_user:
        p.error("LP_USER and --anonymous are mutually exclusive")
    return args


def normalize_ppa(spec):
    """Accept owner/archive, ~owner/archive, reference or full URL -> owner/archive."""
    s = spec.strip()
    m = re.search(r'~([^/]+)/\+archive/ubuntu/([^/?#]+)', s)      # full URL
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    s = s.lstrip("~")
    m = re.match(r'^([^/]+)/ubuntu/([^/]+)$', s)                  # reference form
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    m = re.match(r'^([^/]+)/([^/]+)$', s)                         # owner/archive
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    raise ValueError(f"cannot parse PPA spec {spec!r} (expected owner/archive)")


# ---------------------------------------------------------------------------
# Launchpad login
# ---------------------------------------------------------------------------
def _cache_base():
    """Return (creating it if needed) the base cache directory for this tool."""
    base = os.path.expanduser("~/.cache/pe-ppa-package-stats")
    os.makedirs(base, exist_ok=True)
    return base


def login(args):
    """Log in to Launchpad and return an API handle.

    Logs in anonymously when --anonymous is set; otherwise loads cached OAuth
    credentials for args.lp_user (prompting for browser authorization the first
    time), then verifies and reports the authenticated identity.
    """
    if args.anonymous:
        sys.stderr.write("Logging in anonymously (public PPAs only)...\n")
        return Launchpad.login_anonymously(
            APP_NAME, service_root=args.service_root,
            launchpadlib_dir=_cache_base(), version="devel")

    cred_path = args.credentials_file or os.path.join(
        _cache_base(), f"credentials-{args.lp_user}.txt")

    if os.path.exists(cred_path):
        sys.stderr.write(f"Using cached Launchpad credentials: {cred_path}\n")
        creds = Credentials.load_from_path(cred_path)
    else:
        creds = Credentials(f"{APP_NAME} ({args.lp_user})")
        url = creds.get_request_token(web_root=args.service_root)
        if "allow_permission" not in url:
            url += "&allow_permission=READ_PRIVATE"
        sys.stderr.write(
            "\n=== Launchpad authorization required ===\n"
            f"1. Log in to launchpad.net as '{args.lp_user}'.\n"
            "2. Open this URL in your browser and click 'Authorize' (read-only access):\n\n"
            f"   {url}\n\n"
            "3. Waiting for browser authorization...\n")
        authorized = False
        for _ in range(60):
            try:
                creds.exchange_request_token_for_access_token(web_root=args.service_root)
                authorized = True
                break
            except Exception:  # pylint: disable=broad-exception-caught
                time.sleep(2)

        if not authorized:
            sys.exit("\nERROR: Launchpad authorization timed out. Please run again and approve the URL.")

        os.makedirs(os.path.dirname(cred_path), exist_ok=True)
        creds.save_to_path(cred_path)
        os.chmod(cred_path, 0o600)
        sys.stderr.write(f"Saved credentials to {cred_path} (chmod 600)\n")

    cache = os.path.join(_cache_base(), "http-cache")
    lp = Launchpad(creds, None, None, service_root=args.service_root,
                   version="devel", cache=cache)
    try:
        who = lp.me.name
        if who != args.lp_user:
            sys.stderr.write(f"WARNING: token belongs to '{who}', not "
                             f"'{args.lp_user}'. Continuing anyway.\n")
        else:
            sys.stderr.write(f"Authenticated as '{who}'.\n")
    # Identity check is best-effort; any failure must not abort the run.
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"WARNING: could not verify identity: {exc}\n")
    return lp


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def format_date(val):
    """Format an ISO date string or datetime object as 'YYYY-MM-DD HH:MM:SS'."""
    if not val or str(val).strip().lower() in ("none", "n/a", ""):
        return "none"
    s = str(val).strip()
    s = s.replace("T", " ")
    if "." in s:
        s = s.split(".", maxsplit=1)[0]
    if "+" in s:
        s = s.split("+", maxsplit=1)[0]
    return s.strip()


def _analyze_one(lp, spec, include_archived):
    """Analyze a single PPA.

    Returns (result, skip_reason) with exactly one of the two set: *result* is
    the per-PPA dict on success, otherwise *skip_reason* explains why the PPA
    was skipped.
    """
    owner, archive = spec.split("/", 1)
    ref = f"~{owner}/ubuntu/{archive}"
    try:
        arch = lp.archives.getByReference(reference=ref)
    # Network/API lookups can raise many unrelated error types; skip on any.
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"WARNING: {spec}: lookup failed: {exc}\n")
        return None, f"lookup failed: {exc}"
    if arch is None:
        sys.stderr.write(f"WARNING: {spec}: not found or no access; skipping\n")
        return None, "not found or no access"
    try:
        display = arch.displayname or ""
        archived = "(archived)" in display.lower()
        private = bool(arch.private)
        if archived and not include_archived:
            sys.stderr.write(f"SKIP (archived): {spec}\n")
            return None, "archived"
        pubs = arch.getPublishedSources(status="Published")
        versions = {}
        dates = {}
        for p in pubs:
            name = p.source_package_name
            ver = getattr(p, "source_package_version", "unknown")
            d_pub = getattr(p, "date_published", None) or getattr(p, "date_created", None)
            versions[name] = ver
            dates[name] = format_date(d_pub)
        names = sorted(versions.keys())
    # Network/API fetch can raise many unrelated error types; skip on any.
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"WARNING: {spec}: fetch failed: {exc}\n")
        return None, f"fetch failed: {exc}"

    kernel = [n for n in names if KERNEL_RE.match(n)]
    nonkernel = [n for n in names if not KERNEL_RE.match(n)]
    label = spec
    if archived:
        label += " (archived)"
    elif private:
        label += " (private)"
    sys.stderr.write(f"OK {spec}: non-kernel={len(nonkernel)} kernel={len(kernel)}\n")
    return {
        "spec": spec, "label": label, "private": private, "archived": archived,
        "kernel": kernel, "nonkernel": nonkernel,
        "borderline": [n for n in nonkernel if BORDERLINE_RE.search(n)],
        "versions": versions, "dates": dates,
    }, None


def analyze(lp, specs, include_archived):
    """Fetch each PPA's published sources and split kernel/non-kernel names.

    Returns (results, skipped): *results* is a list of per-PPA dicts and
    *skipped* is a list of (spec, reason) for PPAs that were archived,
    inaccessible, or failed to fetch.
    """
    results, skipped = [], []
    for spec in specs:
        result, reason = _analyze_one(lp, spec, include_archived)
        if result is None:
            skipped.append((spec, reason))
        else:
            results.append(result)
    return results, skipped


def global_unique_counts(results):
    """Return (non_kernel, kernel) package counts deduplicated across all PPAs.

    The summary TOTAL is additive (a package shared by two PPAs is counted in
    each); this collapses those duplicates to count each distinct name once.
    """
    nonkernel, kernel = set(), set()
    for r in results:
        nonkernel.update(r["nonkernel"])
        kernel.update(r["kernel"])
    return len(nonkernel), len(kernel)


def compare_versions(ver_ppa, ver_ubuntu):
    """Compare PPA package version vs Ubuntu archive package version.

    Base is always the PPA package:
      returns -1 if PPA version is older than Ubuntu version ("PPA older")
      returns  0 if PPA version is same as Ubuntu version ("PPA same")
      returns  1 if PPA version is newer than Ubuntu version ("PPA newer")
      returns None if package is not in Ubuntu archive ("PPA only")
    """
    if not ver_ubuntu or ver_ubuntu in ("none", "N/A"):
        return None
    if ver_ppa == ver_ubuntu:
        return 0

    try:
        import apt_pkg
        apt_pkg.init()
        res = apt_pkg.version_compare(ver_ppa, ver_ubuntu)
        if res < 0:
            return -1
        if res > 0:
            return 1
        return 0
    except (ImportError, AttributeError):
        pass

    def _split_epoch(v):
        if ":" in v:
            ep, rest = v.split(":", 1)
            try:
                return int(ep), rest
            except ValueError:
                pass
        return 0, v

    ep1, rest1 = _split_epoch(ver_ppa)
    ep2, rest2 = _split_epoch(ver_ubuntu)
    if ep1 != ep2:
        return -1 if ep1 < ep2 else 1

    def _tok(s):
        parts = []
        curr = ""
        for c in s:
            if c == "~":
                if curr:
                    parts.append(curr)
                    curr = ""
                parts.append("~")
            elif c.isdigit():
                if curr and not curr.isdigit() and curr != "~":
                    parts.append(curr)
                    curr = ""
                curr += c
            else:
                if curr and curr.isdigit():
                    parts.append(int(curr))
                    curr = ""
                curr += c
        if curr:
            parts.append(int(curr) if curr.isdigit() else curr)
        return parts

    t1, t2_toks = _tok(rest1), _tok(rest2)
    for a, b in zip(t1, t2_toks):
        if a == b:
            continue
        if a == "~":
            return -1
        if b == "~":
            return 1
        if isinstance(a, int) and isinstance(b, int):
            return -1 if a < b else 1
        return -1 if str(a) < str(b) else 1

    if len(t1) != len(t2_toks):
        return -1 if len(t1) < len(t2_toks) else 1
    return 0


def version_rel_str(ver_ppa, ver_ubuntu):
    """Return 'PPA older', 'PPA same', 'PPA newer', or 'PPA only'."""
    rel = compare_versions(ver_ppa, ver_ubuntu)
    if rel is None:
        return "PPA only"
    if rel < 0:
        return "PPA older"
    if rel > 0:
        return "PPA newer"
    return "PPA same"


# ---------------------------------------------------------------------------
# Ubuntu archive check
# ---------------------------------------------------------------------------
def _check_ubuntu_via_launchpadlib(packages, series, lp=None):  # pylint: disable=unused-argument
    """Check package availability via the Launchpad REST API.

    Resilient by design: each package is queried independently with a few
    retries, and a single slow/failed request never aborts the whole batch
    (that would drop the valuable publication dates for every package). Only if
    a large fraction of queries fail is a RuntimeError raised so the caller can
    fall back to a coarser checker.

    The *lp* handle is accepted for a consistent interface with the fallback
    checkers but is not needed here (queries go via the public REST API).
    """
    pkg_list = sorted(set(packages))

    def check_one(pkg):
        url = (
            "https://api.launchpad.net/1.0/ubuntu/+archive/primary"
            f"?ws.op=getPublishedSources&exact_match=true&status=Published&source_name={urllib.parse.quote(pkg)}"
        )
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                # Capture every series in one pass (no extra API cost): the REST
                # response lists a Published record per series.
                series_map = {}
                for entry in data.get("entries", []):
                    link = entry.get("distro_series_link", "")
                    sname = link.rstrip("/").split("/")[-1] if link else None
                    if not sname or sname in series_map:
                        continue
                    d_pub = entry.get("date_published") or entry.get("date_created")
                    series_map[sname] = {
                        "version": entry.get("source_package_version"),
                        "date": format_date(d_pub),
                    }
                if series in series_map:
                    info = {
                        "available": True,
                        "version": series_map[series]["version"],
                        "date_published": series_map[series]["date"],
                        "component": "main",
                    }
                else:
                    info = {"available": False, "version": None,
                            "date_published": None, "component": None}
                return pkg, info, series_map, True
            except Exception:  # pylint: disable=broad-exception-caught
                if attempt < 2:
                    time.sleep(1)
        # All attempts failed for this package.
        return pkg, {"available": False, "version": None,
                     "date_published": None, "component": None}, {}, False

    results = {}
    failures = []
    archive_map = {}
    max_workers = min(10, len(pkg_list)) if pkg_list else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for pkg, info, series_map, ok in ex.map(check_one, pkg_list):
            results[pkg] = info
            if series_map:
                archive_map[pkg] = series_map
            if not ok:
                failures.append(pkg)

    # If too many queries failed the availability data is unreliable; signal the
    # caller to fall back rather than silently reporting packages as unavailable.
    if pkg_list and len(failures) > max(3, len(pkg_list) // 10):
        raise RuntimeError(f"{len(failures)}/{len(pkg_list)} Launchpad REST API queries failed")

    return results, failures, archive_map


def _check_ubuntu_via_rmadison_cli(packages, series):
    """Check package availability via rmadison CLI tool."""
    rmadison_bin = shutil.which("rmadison")
    if not rmadison_bin:
        raise RuntimeError("rmadison CLI binary not found in PATH")

    pkg_list = sorted(set(packages))
    results = {
        pkg: {"available": False, "version": None, "date_published": None, "component": None}
        for pkg in pkg_list
    }

    cmd = [rmadison_bin, "-u", "ubuntu", "-s", series] + pkg_list
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if res.returncode != 0 or not res.stdout:
        raise RuntimeError(f"rmadison CLI failed with exit code {res.returncode}")

    for line in res.stdout.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            pkg_name = parts[0]
            version = parts[1]
            location = parts[2]
            comp = location.split("/", 1)[1] if "/" in location else "main"
            if pkg_name in results:
                results[pkg_name] = {
                    "available": True,
                    "version": version,
                    "date_published": None,
                    "component": comp
                }

    return results


def _check_ubuntu_via_web_madison(packages, series):
    """Check package availability via web madison API."""
    pkg_list = sorted(set(packages))
    results = {
        pkg: {"available": False, "version": None, "date_published": None, "component": None}
        for pkg in pkg_list
    }

    url = "https://qa.debian.org/madison.php"
    data = urllib.parse.urlencode({
        "package": " ".join(pkg_list),
        "table": "ubuntu",
        "s": series,
        "text": "on"
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"User-Agent": APP_NAME}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw_output = resp.read().decode("utf-8")

    for line in raw_output.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            pkg_name = parts[0]
            version = parts[1]
            location = parts[2]
            comp = location.split("/", 1)[1] if "/" in location else "main"
            if pkg_name in results:
                results[pkg_name] = {
                    "available": True,
                    "version": version,
                    "date_published": None,
                    "component": comp
                }

    return results


def _requery_failed(failed_pkgs, series):
    """Re-query only the *failed_pkgs* via the fallback checkers (rmadison, web).

    Used for a partial-fallback merge: when the primary Launchpad REST path
    succeeds for most packages but a few individual queries failed, we recover
    availability/version for just those few instead of discarding the whole
    (date-bearing) primary result. Returns a possibly-empty dict.
    """
    if not failed_pkgs:
        return {}
    try:
        return _check_ubuntu_via_rmadison_cli(failed_pkgs, series)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    try:
        return _check_ubuntu_via_web_madison(failed_pkgs, series)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return {}


def check_ubuntu_availability(packages, series="stonking", lp=None, meta=None):
    """Check availability of package names in the specified Ubuntu archive series.

    Preference order:
      1. Launchpad REST API (primary; returns publication dates)
      2. rmadison CLI tool (fallback 1; no dates)
      3. web madison API (fallback 2; no dates)

    If the primary path succeeds for most packages but a few individual queries
    fail, only those are re-queried via the fallbacks and merged in (so the
    valuable publication dates for the rest are preserved).

    Returns a dict mapping package_name -> dict:
      {"available": bool, "version": str|None, "date_published": str|None,
       "component": str|None}

    If *meta* is a dict, it is populated with:
      - "ubuntu_source": one of launchpad-api, launchpad-api+partial-fallback,
        rmadison, web-madison, none
      - "archive_map": {package -> {series -> {"version", "date"}}} for every
        Ubuntu series seen (only from the primary REST path; empty otherwise)

    # TODO: point-in-time archive versions (Superseded publication history) would
    # give the exact version present in a series on a past date (Option 3).
    """
    def _set_source(src):
        if meta is not None:
            meta["ubuntu_source"] = src

    def _set_archive(amap):
        if meta is not None:
            meta["archive_map"] = amap

    if not packages:
        _set_source("none")
        _set_archive({})
        return {}

    # 1. Prefer the Launchpad REST API.
    try:
        results, failed, archive_map = _check_ubuntu_via_launchpadlib(packages, series, lp=lp)
        source = "launchpad-api"
        if failed:
            merged = _requery_failed(failed, series)
            if merged:
                sys.stderr.write(
                    f"NOTE: {len(failed)} package(s) failed the Launchpad REST API; "
                    "recovered via fallback (no dates for those).\n"
                )
                for pkg, info in merged.items():
                    results[pkg] = info
                source = "launchpad-api+partial-fallback"
        _set_source(source)
        _set_archive(archive_map)
        return results
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"WARNING: launchpadlib API check failed ({exc}); falling back to rmadison CLI tool...\n")

    _set_archive({})

    # 2. Fall back to the rmadison CLI tool.
    try:
        res = _check_ubuntu_via_rmadison_cli(packages, series)
        _set_source("rmadison")
        return res
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"WARNING: rmadison CLI tool failed ({exc}); falling back to web madison API...\n")

    # 3. Fall back to the web madison API.
    try:
        res = _check_ubuntu_via_web_madison(packages, series)
        _set_source("web-madison")
        return res
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(f"WARNING: web madison API check failed ({exc}).\n")
        _set_source("none")
        return {
            pkg: {"available": False, "version": None, "date_published": None, "component": None}
            for pkg in sorted(set(packages))
        }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def build_table(results):
    """Render *results* as an ASCII summary table (PPA, Non-kernel, Kernel).

    Returns (table_str, total_non_kernel, total_kernel).
    """
    rows = [(r["label"], len(r["nonkernel"]), len(r["kernel"])) for r in results]
    tot_nk = sum(r[1] for r in rows)
    tot_k = sum(r[2] for r in rows)
    w = max([len(r[0]) for r in rows] + [len("PPA"), len("TOTAL")])
    c_nk = max([len(str(r[1])) for r in rows] + [len(str(tot_nk)), len("Non-kernel")]) + 2
    c_k = max([len(str(r[2])) for r in rows] + [len(str(tot_k)), len("Kernel")]) + 2
    sep = ("+" + "-" * (w + 2) + "+" + "-" * (c_nk + 2) + "+"
           + "-" * (c_k + 2) + "+")

    def row(a, b, c):
        return (f"| {str(a).ljust(w)} | {str(b).center(c_nk)} "
                f"| {str(c).center(c_k)} |")

    lines = [sep, row("PPA", "Non-kernel", "Kernel"), sep]
    lines += [row(*r) for r in rows]
    lines.append(sep)
    lines.append(row("TOTAL", tot_nk, tot_k))
    lines.append(sep)
    return "\n".join(lines), tot_nk, tot_k


def write_details_csv(path, results, ubuntu_info=None, series="stonking"):
    """Write row-per-package detailed CSV with package names, types, PPA versions, arrival dates, and Ubuntu archive versions."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if ubuntu_info:
            w.writerow([
                "PPA",
                "Package",
                "Type",
                "Version in PPA",
                "Date/Time arrived in PPA",
                f"Version in Ubuntu {series}",
                f"Date/Time arrived in Ubuntu {series}",
                "Comparison (PPA vs Archive)"
            ])
            for r in results:
                versions = r.get("versions", {})
                dates = r.get("dates", {})
                for p in r["nonkernel"]:
                    p_ver = versions.get(p, "unknown")
                    p_date = dates.get(p, "none")
                    info = ubuntu_info.get(p, {})
                    u_ver = info.get("version") if info.get("available") else None
                    u_date = info.get("date_published") if info.get("available") else None
                    u_ver_str = u_ver or "none"
                    u_date_str = u_date or "none"
                    rel = version_rel_str(p_ver, u_ver)
                    w.writerow([r["label"], p, "non-kernel", p_ver, p_date, u_ver_str, u_date_str, rel])
                for p in r["kernel"]:
                    p_ver = versions.get(p, "unknown")
                    p_date = dates.get(p, "none")
                    w.writerow([r["label"], p, "kernel", p_ver, p_date, "N/A", "N/A", "N/A"])
        else:
            w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA"])
            for r in results:
                versions = r.get("versions", {})
                dates = r.get("dates", {})
                for p in r["nonkernel"]:
                    p_ver = versions.get(p, "unknown")
                    p_date = dates.get(p, "none")
                    w.writerow([r["label"], p, "non-kernel", p_ver, p_date])
                for p in r["kernel"]:
                    p_ver = versions.get(p, "unknown")
                    p_date = dates.get(p, "none")
                    w.writerow([r["label"], p, "kernel", p_ver, p_date])


def _txt_notes(results, skipped):
    """Build the NOTES section lines of the text report."""
    out = ["NOTES", "=" * 5]
    a = out.append
    g_nk, g_k = global_unique_counts(results)
    a("  The TOTAL row is additive: a package published in two PPAs is counted in each, so TOTAL can exceed the number of distinct packages.")
    a(f"  Distinct across ALL PPAs (each name counted once): {g_nk} non-kernel, {g_k} kernel-related.")
    any_border = False
    for r in results:
        if r["borderline"]:
            any_border = True
            a(f"  Borderline (builds kernel modules, kept as non-kernel) in {r['label']}: {', '.join(r['borderline'])}")
    if not any_border:
        a("  No borderline kernel-module packages detected.")
    seen = {}
    for r in results:
        seen.setdefault(tuple(r["nonkernel"]), []).append(r["label"])
    for key, labels in seen.items():
        if len(labels) > 1 and key:
            a(f"  Identical non-kernel package set ({len(key)} pkgs): {', '.join(labels)}")
    for spec, reason in skipped:
        a(f"  Skipped {spec}: {reason}")
    return out


def build_txt(results, skipped, table_str, args, ubuntu_info=None):
    """Build the full text report (table, package lists separated by non-kernel/kernel, notes)."""
    tot_nk = sum(len(r["nonkernel"]) for r in results)
    tot_k = sum(len(r["kernel"]) for r in results)
    out = []
    a = out.append
    a("PPA package count analysis")
    a("=" * 27)
    a("")
    a("Method: Launchpad getPublishedSources (status=Published) via launchpadlib.")
    a("Names deduplicated (same name, different versions/series counted once).")
    a('Kernel filter excludes source names matching "linux*" or "flash-kernel*".')
    mode = "anonymous" if args.anonymous else f"authenticated as {args.lp_user}"
    a(f"Auth mode: {mode}.")
    a(f"Archived PPAs are {'included' if args.include_archived else 'skipped'}.")
    series = str(getattr(args, "ubuntu_series", None) or get_devel_series_for_date(datetime.now()) or "stonking")
    if ubuntu_info:
        a(f"Ubuntu archive availability check: enabled (release series: {series}).")
    a("")
    a("")
    a("SUMMARY TABLE")
    a("=" * 13)
    a("")
    a(table_str)
    a("")
    a("")
    a("FULL PACKAGE LISTS")
    a("=" * 18)
    for r in results:
        a("")
        title = f"{r['label']} ({len(r['nonkernel'])} non-kernel, {len(r['kernel'])} kernel-related)"
        a(title)
        a("-" * len(title))
        a("  Non-kernel packages:")
        if r["nonkernel"]:
            for n in r["nonkernel"]:
                p_ver = r.get("versions", {}).get(n, "unknown")
                if ubuntu_info:
                    info = ubuntu_info.get(n, {})
                    u_ver = info.get("version") if info.get("available") else None
                    rel = version_rel_str(p_ver, u_ver)
                    u_ver_str = u_ver or "none"
                    a(f"    {n}  (PPA: {p_ver} | {series}: {u_ver_str} [{rel}])")
                else:
                    a(f"    {n}  (PPA: {p_ver})")
        else:
            a("    none")
        a("  Kernel-related packages:")
        if r["kernel"]:
            for n in r["kernel"]:
                p_ver = r.get("versions", {}).get(n, "unknown")
                a(f"    {n}  (PPA: {p_ver})")
        else:
            a("    none")

    if ubuntu_info:
        a("")
        a("")
        a(f"UBUNTU ARCHIVE AVAILABILITY (series: {series})")
        a("=" * (32 + len(series)))
        a("Note: Base is always PPA package vs Ubuntu archive (PPA older / same / newer than archive).")
        all_nk = sorted({pkg for r in results for pkg in r["nonkernel"]})
        c_older, c_same, c_newer, c_only = 0, 0, 0, 0
        for p in all_nk:
            info = ubuntu_info.get(p, {})
            u_ver = info.get("version") if info.get("available") else None
            p_ver = "unknown"
            for r in results:
                if p in r.get("versions", {}):
                    p_ver = r["versions"][p]
                    break
            rel = version_rel_str(p_ver, u_ver)
            if rel == "PPA older":
                c_older += 1
            elif rel == "PPA same":
                c_same += 1
            elif rel == "PPA newer":
                c_newer += 1
            else:
                c_only += 1

        tot_distinct = len(all_nk)
        a(f"Total distinct non-kernel packages checked: {tot_distinct}")
        a(f"  - PPA older than Ubuntu {series}: {c_older} ({(c_older/tot_distinct*100):.1f}%)" if tot_distinct else f"  - PPA older: {c_older}")
        a(f"  - PPA same as Ubuntu {series}:   {c_same} ({(c_same/tot_distinct*100):.1f}%)" if tot_distinct else f"  - PPA same: {c_same}")
        a(f"  - PPA newer than Ubuntu {series}:  {c_newer} ({(c_newer/tot_distinct*100):.1f}%)" if tot_distinct else f"  - PPA newer: {c_newer}")
        a(f"  - PPA only (NOT in Ubuntu {series}): {c_only} ({(c_only/tot_distinct*100):.1f}%)" if tot_distinct else f"  - PPA only: {c_only}")

    a("")
    a("")
    out.extend(_txt_notes(results, skipped))
    a("")
    a(f"Totals: {tot_nk} unique non-kernel packages, {tot_k} kernel-related packages.")
    return "\n".join(out) + "\n"


def build_json(results, skipped, args, ubuntu_info=None):
    """Build a JSON-serializable dict describing the full analysis."""
    tot_nk = sum(len(r["nonkernel"]) for r in results)
    tot_k = sum(len(r["kernel"]) for r in results)
    g_nk, g_k = global_unique_counts(results)
    series = getattr(args, "ubuntu_series", "stonking")
    doc = {
        "auth_mode": "anonymous" if args.anonymous else "authenticated",
        "lp_user": None if args.anonymous else args.lp_user,
        "include_archived": bool(args.include_archived),
        "ubuntu_series": series if not getattr(args, "no_ubuntu_check", False) else None,
        "ppas": [
            {
                "spec": r["spec"],
                "label": r["label"],
                "private": r["private"],
                "archived": r["archived"],
                "non_kernel_count": len(r["nonkernel"]),
                "kernel_count": len(r["kernel"]),
                "non_kernel": r["nonkernel"],
                "kernel": r["kernel"],
                "borderline": r["borderline"],
            }
            for r in results
        ],
        "skipped": [{"spec": spec, "reason": reason} for spec, reason in skipped],
        "totals": {
            "non_kernel_additive": tot_nk,
            "kernel_additive": tot_k,
            "non_kernel_distinct_across_ppas": g_nk,
            "kernel_distinct_across_ppas": g_k,
        },
    }
    if ubuntu_info:
        for ppa_entry in doc["ppas"]:
            nk_list = ppa_entry["non_kernel"]
            ppa_entry["ubuntu_availability"] = {
                pkg: ubuntu_info.get(pkg, {"available": False})
                for pkg in nk_list
            }
    return doc


def ubuntu_date_coverage(all_nk, ubuntu_info):
    """Return a coverage dict describing how many packages carry archive dates.

    Only packages that are available in the archive can have an arrival date, so
    the headline percentage is expressed relative to the available count.
    """
    ubuntu_info = ubuntu_info or {}
    total = len(all_nk)
    available = sum(1 for p in all_nk if ubuntu_info.get(p, {}).get("available"))
    dated = sum(1 for p in all_nk
                if parse_csv_date(ubuntu_info.get(p, {}).get("date_published")) is not None)
    pct = (dated / available * 100) if available else 0.0
    return {
        "distinct_non_kernel": total,
        "available_in_ubuntu": available,
        "with_arrival_date": dated,
        "date_coverage_pct_of_available": round(pct, 1),
    }


def archive_date_coverage(all_nk, archive, series):
    """Coverage of arrival dates for *series* using the multi-series archive map."""
    total = len(all_nk)
    available = dated = 0
    for p in all_nk:
        ver, date = archive_ver_date(archive, p, series)
        if ver is not None:
            available += 1
            if parse_csv_date(date) is not None:
                dated += 1
    pct = (dated / available * 100) if available else 0.0
    return {
        "distinct_non_kernel": total,
        "available_in_ubuntu": available,
        "with_arrival_date": dated,
        "date_coverage_pct_of_available": round(pct, 1),
    }


def _archive_series_seen(archive_map):
    """Return the sorted set of Ubuntu series present in an archive map."""
    seen = set()
    for series_map in (archive_map or {}).values():
        seen.update(series_map.keys())
    return sorted(seen)


def build_scan_meta(results, skipped, ubuntu_info, series, ubuntu_source, args, archive_map=None):
    """Build the scan-metadata (side-car) dict recording data provenance."""
    g_nk, g_k = global_unique_counts(results)
    all_nk = sorted({pkg for r in results for pkg in r["nonkernel"]})
    if getattr(args, "test", False):
        auth_mode = "test-mode"
    elif args.anonymous:
        auth_mode = "anonymous"
    else:
        auth_mode = "authenticated"
    return {
        "tool": APP_NAME,
        "tool_version": TOOL_VERSION,
        "execution_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "auth_mode": auth_mode,
        "lp_user": None if args.anonymous else getattr(args, "lp_user", None),
        "ubuntu_series": series,
        "ubuntu_source": ubuntu_source,
        "archive_series_seen": _archive_series_seen(archive_map),
        "analyzed_ppas": len(results),
        "skipped_ppas": [{"spec": spec, "reason": reason} for spec, reason in skipped],
        "totals": {
            "non_kernel_additive": sum(len(r["nonkernel"]) for r in results),
            "kernel_additive": sum(len(r["kernel"]) for r in results),
            "non_kernel_distinct": g_nk,
            "kernel_distinct": g_k,
        },
        "ubuntu_coverage": ubuntu_date_coverage(all_nk, ubuntu_info),
    }


def write_scan_meta(path, meta):
    """Write the scan-metadata dict to *path* as pretty JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")


def write_archive_map(path, archive_map, scan_series):
    """Write the multi-series Ubuntu archive map to *path* as pretty JSON."""
    doc = {
        "tool": APP_NAME,
        "tool_version": TOOL_VERSION,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_series": scan_series,
        "series_seen": _archive_series_seen(archive_map),
        "packages": archive_map,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def load_latest_archive_map(outdir="."):
    """Load the latest pe-ppa-package-archive_*.json side-car.

    Returns (packages_map, series_seen). Both are empty if none is found.
    """
    files = sorted(glob.glob(os.path.join(outdir, "pe-ppa-package-archive_*.json")))
    if not files:
        return {}, []
    try:
        with open(files[-1], "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        packages = doc.get("packages", {}) or {}
        series_seen = doc.get("series_seen") or _archive_series_seen(packages)
        return packages, series_seen
    except (OSError, ValueError):
        return {}, []


def archive_ver_date(archive_map, pkg, series):
    """Return (version, date) for *pkg* in *series* from the archive map, else (None, None)."""
    entry = (archive_map or {}).get(pkg, {}).get(series)
    if entry:
        return entry.get("version"), entry.get("date")
    return None, None


UBUNTU_SERIES_TIMELINE = [
    ("jammy", "22.04", "2021-10-15", "2022-04-21"),
    ("kinetic", "22.10", "2022-04-26", "2022-10-20"),
    ("lunar", "23.04", "2022-10-27", "2023-04-20"),
    ("mantic", "23.10", "2023-04-25", "2023-10-16"),
    ("noble", "24.04", "2023-10-23", "2024-04-25"),
    ("oracular", "24.10", "2024-04-29", "2024-10-11"),
    ("plucky", "25.04", "2024-10-17", "2025-04-17"),
    ("questing", "25.10", "2025-04-22", "2025-10-09"),
    ("resolute", "26.04", "2025-10-09", "2026-04-23"),
    ("stonking", "26.10", "2026-04-24", "9999-12-31"),
]


def get_current_devel_series():
    """Discover the current active Ubuntu development release codename from Launchpad."""
    # 1. Try Launchpad REST API
    try:
        url = "https://api.launchpad.net/1.0/ubuntu"
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            link = data.get("current_series_link", "")
            if link:
                codename = link.rstrip("/").split("/")[-1]
                if codename:
                    return str(codename)
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # 2. Fallback to launchpad.net/ubuntu web page
    try:
        url = "https://launchpad.net/ubuntu"
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8")
            m = re.search(r"\"current_series_link\":\s*\"[^\"]*/ubuntu/([a-z]+)\"", html)
            if m:
                return m.group(1)
            m = re.search(r"href=\"/ubuntu/([a-z]+)\"[^>]*class=\"sprite distribution\"", html)
            if m:
                return m.group(1)
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    return "stonking"


def get_devel_series_for_date(target_dt=None):
    """Determine which Ubuntu release series was in active development on target_dt."""
    if not target_dt or target_dt.date() >= datetime.now().date():
        return get_current_devel_series()

    dt_str = target_dt.strftime("%Y-%m-%d")
    timeline = UBUNTU_SERIES_TIMELINE
    try:
        url = "https://api.launchpad.net/1.0/ubuntu/series"
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            fetched = []
            for entry in data.get("entries", []):
                name = entry.get("name")
                ver = entry.get("version") or ""
                created = (entry.get("date_created") or "1970-01-01")[:10]
                released = (entry.get("datereleased") or "9999-12-31")[:10]
                if name:
                    fetched.append((name, ver, created, released))
            if fetched:
                timeline = fetched
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    for name, _ver, created, released in timeline:
        if created <= dt_str <= released and name:
            return str(name)

    return get_current_devel_series()


def parse_target_date(val):
    """Parse a date string like '20260101' or '2026-01-01' into a datetime object (end of day 23:59:59)."""
    if not val or str(val).lower() in ("latest", "today", "true", "none"):
        return datetime.now()
    s = str(val).strip().replace("-", "").replace("/", "")
    if len(s) == 8 and s.isdigit():
        return datetime(int(s[:4]), int(s[4:6]), int(s[6:8]), 23, 59, 59)
    try:
        return datetime.fromisoformat(val)
    except ValueError:
        return datetime.now()


def parse_csv_date(dt_str):
    """Parse a date string from CSV into a datetime object."""
    if not dt_str or str(dt_str).lower() in ("none", "n/a", ""):
        return None
    try:
        s = str(dt_str).strip().replace("T", " ")
        if "." in s:
            s = s.split(".", maxsplit=1)[0]
        if "+" in s:
            s = s.split("+", maxsplit=1)[0]
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.strptime(str(dt_str).strip()[:10], "%Y-%m-%d")
        except ValueError:
            return None


def _arrived_by(date_str, target_dt):
    """True if a PPA arrival date is unknown, or on/before target_dt (historical filter)."""
    dt = parse_csv_date(date_str)
    return dt is None or dt <= target_dt


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
_NO_UBUNTU_DATES_WARNING = (
    "WARNING: no 'arrived in Ubuntu' dates are available in the scan data.\n"
    "         Historical / quarterly PPA-vs-archive comparison is therefore\n"
    "         unreliable: packages present in the archive cannot be confirmed\n"
    "         as-of a past date and all fall into 'PPA only'.\n"
    "         This happens when the scan used the rmadison/web fallback instead\n"
    "         of the Launchpad REST API. Re-run a scan (primary API) to capture\n"
    "         archive publication dates for accurate historical statistics.\n"
)


def _has_ubuntu_dates_in_csv(csv_path):
    """Return True if the detailed CSV has at least one Ubuntu arrival date set."""
    try:
        with open(csv_path, "r", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            date_col = None
            for col in reader.fieldnames or []:
                if "arrived in Ubuntu" in col:
                    date_col = col
            if not date_col:
                return False
            for r in reader:
                if parse_csv_date(r.get(date_col)) is not None:
                    return True
    except OSError:
        return False
    return False


def _has_ubuntu_dates_in_info(ubuntu_info):
    """Return True if any ubuntu_info entry carries a publication date."""
    if not ubuntu_info:
        return False
    return any(parse_csv_date(v.get("date_published")) is not None
               for v in ubuntu_info.values())


def _csv_ubuntu_coverage(csv_path):
    """Coverage of Ubuntu arrival dates among distinct non-kernel packages in a CSV.

    Returns {distinct_non_kernel, available_in_ubuntu, with_arrival_date,
    date_coverage_pct_of_available}. The percentage is relative to the packages
    that are actually present in the archive (only those can carry a date).
    """
    seen = {}
    try:
        with open(csv_path, "r", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            ver_col = None
            date_col = None
            for c in reader.fieldnames or []:
                if c.startswith("Version in Ubuntu"):
                    ver_col = c
                if "arrived in Ubuntu" in c:
                    date_col = c
            for r in reader:
                if r.get("Type") != "non-kernel":
                    continue
                pkg = r.get("Package")
                if pkg in seen:
                    continue
                ver = (r.get(ver_col) if ver_col else None) or r.get("Version in stonking")
                avail = ver not in (None, "none", "N/A", "")
                dated = parse_csv_date(r.get(date_col)) is not None if date_col else False
                seen[pkg] = (avail, dated)
    except OSError:
        pass
    total = len(seen)
    available = sum(1 for a, _d in seen.values() if a)
    dated = sum(1 for _a, d in seen.values() if d)
    pct = (dated / available * 100) if available else 0.0
    return {
        "distinct_non_kernel": total,
        "available_in_ubuntu": available,
        "with_arrival_date": dated,
        "date_coverage_pct_of_available": round(pct, 1),
    }


def _coverage_metric_line(cov):
    """Format the Ubuntu arrival-date coverage as an aligned OVERALL METRICS line."""
    label = "Ubuntu arrival-date coverage:"
    return (f"  {label:<36} {cov['with_arrival_date']:>5} / {cov['available_in_ubuntu']} "
            f"available ({cov['date_coverage_pct_of_available']:.1f}%)")


def _csv_scanned_series(fieldnames):
    """Extract the Ubuntu series the CSV was scanned against, from its headers."""
    for col in fieldnames or []:
        if col.startswith("Version in Ubuntu "):
            return col[len("Version in Ubuntu "):].strip()
        if col.startswith("Date/Time arrived in Ubuntu "):
            return col[len("Date/Time arrived in Ubuntu "):].strip()
    return None


def _csv_scanned_ubuntu_version(row):
    """Return the (scanned-series) Ubuntu version recorded on a detailed-CSV row."""
    for key, val in row.items():
        if key and key.startswith("Version in Ubuntu"):
            return val
    return row.get("Version in stonking")


def _series_mismatch_note(target_series, scanned_series):
    """Return a note string when reporting a series not covered by the scan snapshot."""
    return (
        f"NOTE: report series '{target_series}' differs from the scanned archive "
        f"snapshot '{scanned_series}', and no multi-series archive data for "
        f"'{target_series}' is available; the comparison uses the '{scanned_series}' "
        "snapshot as an approximation (re-scan to capture multi-series data).\n"
    )


def _rel_counts(rels):
    """Return (older, same, newer, only) counts from an iterable of comparison strings."""
    older = same = newer = only = 0
    for rel in rels:
        older += rel == "PPA older"
        same += rel == "PPA same"
        newer += rel == "PPA newer"
        only += rel == "PPA only"
    return older, same, newer, only


_PER_PPA_HDR = (f"  {'PPA':<45} | {'Non-Kernel':<10} | {'PPA older':<9} | {'PPA same':<8} | "
                f"{'PPA newer':<9} | {'PPA only':<8} | {'Kernel':<7}")


def _rep_date_str(is_historical, target_dt):
    """Return the human-readable 'Reporting date' suffix for report headers."""
    if is_historical:
        return target_dt.strftime("%Y-%m-%d") + f" (status as of {target_dt.strftime('%Y-%m-%d')})"
    return datetime.now().strftime("%Y-%m-%d - %H:%M:%S") + " (status as of today)"


def _write_report_header(series_label, rep_date_str):
    """Write the shared REPORTING PHASE header block."""
    exec_date = datetime.now().strftime("%Y-%m-%d - %H:%M:%S")
    sys.stdout.write("\n" + "=" * 95 + "\n")
    sys.stdout.write("REPORTING PHASE\n")
    sys.stdout.write(series_label + "\n")
    sys.stdout.write(f"Execution date: {exec_date}\n")
    sys.stdout.write(f"Reporting date: {rep_date_str}\n")
    sys.stdout.write("Note: Base is always PPA package vs Ubuntu archive "
                     "(PPA older / same / newer than archive)\n")
    sys.stdout.write("=" * 95 + "\n")


def _per_ppa_from_items(nk_items, k_items, rel_fn):
    """Build per-PPA aggregate rows from CSV (row, ubuntu-col) item tuples."""
    per_ppa = []
    for ppa in sorted({it[0]["PPA"] for it in nk_items + k_items}):
        p_nk = [it for it in nk_items if it[0]["PPA"] == ppa]
        p_k = [it for it in k_items if it[0]["PPA"] == ppa]
        older, same, newer, only = _rel_counts(rel_fn(r, u) for r, u in p_nk)
        per_ppa.append({
            "ppa": ppa, "non_kernel": len(p_nk), "kernel": len(p_k),
            "ppa_older": older, "ppa_same": same, "ppa_newer": newer, "ppa_only": only,
        })
    return per_ppa


def _overlap_from_items(nk_items):
    """Return {package: [ppas]} for packages published in more than one PPA."""
    pkg_ppas = {}
    for it in nk_items:
        pkg_ppas.setdefault(it[0]["Package"], set()).add(it[0]["PPA"])
    return {p: sorted(s) for p, s in pkg_ppas.items() if len(s) > 1}


def _aggregate_csv_items(rows, rel_fn):
    """Aggregate CSV report rows into distinct counts, per-PPA rows and overlap."""
    nk_items = [it for it in rows if it[0]["Type"] == "non-kernel"]
    k_items = [it for it in rows if it[0]["Type"] == "kernel"]
    distinct = {}
    for r, u_col in nk_items:
        distinct.setdefault(r["Package"], rel_fn(r, u_col))
    return {
        "analyzed_ppas": len({it[0]["PPA"] for it in rows}),
        "distinct": distinct,
        "kernel_names": {it[0]["Package"] for it in k_items},
        "per_ppa": _per_ppa_from_items(nk_items, k_items, rel_fn),
        "shared": _overlap_from_items(nk_items),
    }


def _write_per_ppa_breakdown(per_ppa, with_ubuntu=True):
    """Write the shared PER-PPA BREAKDOWN table."""
    sys.stdout.write("\n=== PER-PPA BREAKDOWN ===\n\n")
    sys.stdout.write(_PER_PPA_HDR + "\n")
    sys.stdout.write("  " + "-" * (len(_PER_PPA_HDR) - 2) + "\n")
    for e in per_ppa:
        if with_ubuntu:
            sys.stdout.write(f"  {e['ppa']:<45} | {e['non_kernel']:^10} | {e['ppa_older']:^9} | "
                             f"{e['ppa_same']:^8} | {e['ppa_newer']:^9} | {e['ppa_only']:^8} | "
                             f"{e['kernel']:^7}\n")
        else:
            sys.stdout.write(f"  {e['ppa']:<45} | {e['non_kernel']:^10} | {'N/A':^9} | "
                             f"{'N/A':^8} | {'N/A':^9} | {'N/A':^8} | {e['kernel']:^7}\n")


def _write_overlap_section(shared):
    """Write the shared PACKAGE OVERLAP section and trailing rule."""
    sys.stdout.write("\n=== PACKAGE OVERLAP (Published in >1 PPA) ===\n\n")
    sys.stdout.write(f"  Distinct packages published in multiple PPAs: {len(shared)}\n")
    for p, p_list in sorted(shared.items()):
        sys.stdout.write(f"    - {p} ({len(p_list)} PPAs): {', '.join(p_list)}\n")
    sys.stdout.write("=" * 95 + "\n\n")


def _filter_results_by_date(results, is_historical, target_dt):
    """Return scan results with packages filtered to those arrived by target_dt."""
    filtered = []
    for r in results:
        dates = r.get("dates", {})
        nk = [p for p in r["nonkernel"] if not is_historical or _arrived_by(dates.get(p), target_dt)]
        k = [p for p in r["kernel"] if not is_historical or _arrived_by(dates.get(p), target_dt)]
        filtered.append({"spec": r["spec"], "label": r["label"], "nonkernel": nk,
                         "kernel": k, "versions": r.get("versions", {}), "dates": dates})
    return filtered


def _memory_rel_fn(udata, series, target_dt, is_historical):
    """Return (rel_fn, has_target_series) computing PPA-vs-archive comparison in memory."""
    has_series = bool(udata.archive) and series in (udata.series_seen or [])

    def _rel(pkg, p_ver):
        if is_historical and has_series:
            u_ver, u_date_s = archive_ver_date(udata.archive, pkg, series)
            u_dt = parse_csv_date(u_date_s)
            u_avail = u_ver is not None and (u_dt is not None and u_dt <= target_dt)
            return version_rel_str(p_ver, u_ver if u_avail else None)
        u_info = udata.info.get(pkg, {}) if udata.info else {}
        u_dt = parse_csv_date(u_info.get("date_published"))
        u_avail = u_info.get("available") and (not is_historical or (u_dt is not None and u_dt <= target_dt))
        return version_rel_str(p_ver, u_info.get("version") if u_avail else None)

    return _rel, has_series


def _memory_global_versions(filtered_results):
    """Return a first-seen {package: version} map across all filtered PPA results."""
    gv = {}
    for r in filtered_results:
        for pkg, ver in r.get("versions", {}).items():
            gv.setdefault(pkg, ver)
    return gv


def _memory_per_ppa(filtered_results, with_ubuntu, rel_fn):
    """Build per-PPA aggregate rows for in-memory scan results."""
    per_ppa = []
    for r in filtered_results:
        entry = {"ppa": r["label"], "non_kernel": len(r["nonkernel"]), "kernel": len(r["kernel"])}
        if with_ubuntu:
            versions = r.get("versions", {})
            older, same, newer, only = _rel_counts(
                rel_fn(p, versions.get(p, "unknown")) for p in r["nonkernel"])
            entry.update(ppa_older=older, ppa_same=same, ppa_newer=newer, ppa_only=only)
        per_ppa.append(entry)
    return per_ppa


def _memory_overlap(filtered_results):
    """Return {package: [ppas]} for packages published in more than one PPA."""
    pkg_ppas = {}
    for r in filtered_results:
        for p in r["nonkernel"]:
            pkg_ppas.setdefault(p, []).append(r["label"])
    return {p: sorted(v) for p, v in pkg_ppas.items() if len(v) > 1}


def _memory_metrics(filtered_results, with_ubuntu, rel_fn):
    """Compute distinct counts, comparison totals, per-PPA rows and overlap."""
    all_nk = sorted({pkg for r in filtered_results for pkg in r["nonkernel"]})
    gvers = _memory_global_versions(filtered_results)
    if with_ubuntu:
        older, same, newer, only = _rel_counts(rel_fn(p, gvers.get(p, "unknown")) for p in all_nk)
    else:
        older = same = newer = only = 0
    return {
        "all_nk": all_nk, "older": older, "same": same, "newer": newer, "only": only,
        "per_ppa": _memory_per_ppa(filtered_results, with_ubuntu, rel_fn),
        "shared": _memory_overlap(filtered_results),
    }


def _write_memory_overall(series, stats, with_ubuntu):
    """Write the OVERALL METRICS block for an in-memory report."""
    dist = len(stats["all_nk"])
    sys.stdout.write("\n=== OVERALL METRICS ===\n\n")
    sys.stdout.write(f"  {'Analyzed PPAs:':<36} {stats['analyzed_ppas']:>5}\n")
    sys.stdout.write(f"  {'Total Non-Kernel Package Entries:':<36} {stats['tot_nk']:>5} (additive)\n")
    sys.stdout.write(f"  {'Total Kernel Package Entries:':<36} {stats['tot_k']:>5} (additive)\n")
    sys.stdout.write(f"  {'Distinct Non-Kernel Packages:':<36} {stats['g_nk']:>5}\n")
    sys.stdout.write(f"  {'Distinct Kernel Packages:':<36} {stats['g_k']:>5}\n")
    if with_ubuntu:
        for label, key in ((f"PPA older than Ubuntu ({series}):", "older"),
                           (f"PPA same as Ubuntu ({series}):", "same"),
                           (f"PPA newer than Ubuntu ({series}):", "newer"),
                           (f"PPA only (NOT in Ubuntu {series}):", "only")):
            val = stats[key]
            pct = (val / dist * 100) if dist else 0
            sys.stdout.write(f"  {label:<36} {val:>5} ({pct:>5.1f}%)\n")
        if stats["is_historical"] and stats["coverage"]:
            sys.stdout.write(_coverage_metric_line(stats["coverage"]) + "\n")


def _memory_report_doc(series, stats):
    """Build the JSON document for an in-memory report."""
    return {
        "tool": APP_NAME,
        "tool_version": TOOL_VERSION,
        "execution_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": stats["mode"],
        "reporting_date": stats["reporting_date"],
        "ubuntu_series": series,
        "analyzed_ppas": stats["analyzed_ppas"],
        "totals": {
            "non_kernel_additive": stats["tot_nk"], "kernel_additive": stats["tot_k"],
            "non_kernel_distinct": stats["g_nk"], "kernel_distinct": stats["g_k"],
            "ppa_older": stats["older"], "ppa_same": stats["same"],
            "ppa_newer": stats["newer"], "ppa_only": stats["only"],
        },
        "ubuntu_coverage": stats["coverage"],
        "per_ppa": stats["per_ppa"],
        "package_overlap": stats["shared"],
    }


def _report_from_in_memory(results, series="stonking", target_date_str="today",
                           as_json=False, udata=None):
    """Format and print statistics from in-memory scan results as of target_date_str."""
    udata = udata or UbuntuData()
    ubuntu_info = udata.info
    with_ubuntu = bool(ubuntu_info)
    target_dt = parse_target_date(target_date_str)
    is_historical = target_date_str not in ("today", "latest", None)
    if is_historical and ubuntu_info and not _has_ubuntu_dates_in_info(ubuntu_info):
        sys.stderr.write(_NO_UBUNTU_DATES_WARNING)

    rel_fn, has_series = _memory_rel_fn(udata, series, target_dt, is_historical)
    if is_historical and not has_series and udata.scan_series and series != udata.scan_series:
        sys.stderr.write(_series_mismatch_note(series, udata.scan_series))

    filtered = _filter_results_by_date(results, is_historical, target_dt)
    stats = _memory_metrics(filtered, with_ubuntu, rel_fn)
    stats["analyzed_ppas"] = len(filtered)
    stats["tot_nk"] = sum(len(r["nonkernel"]) for r in filtered)
    stats["tot_k"] = sum(len(r["kernel"]) for r in filtered)
    stats["g_nk"], stats["g_k"] = global_unique_counts(filtered)
    stats["is_historical"] = is_historical
    stats["mode"] = "historical" if is_historical else "today"
    stats["reporting_date"] = (target_dt.strftime("%Y-%m-%d") if is_historical
                               else datetime.now().strftime("%Y-%m-%d"))
    if has_series:
        stats["coverage"] = archive_date_coverage(stats["all_nk"], udata.archive, series)
    elif ubuntu_info:
        stats["coverage"] = ubuntu_date_coverage(stats["all_nk"], ubuntu_info)
    else:
        stats["coverage"] = None

    if as_json:
        sys.stdout.write(json.dumps(_memory_report_doc(series, stats), indent=2) + "\n")
        return

    _write_report_header(f"(Ubuntu Series: {series})", _rep_date_str(is_historical, target_dt))
    _write_memory_overall(series, stats, with_ubuntu)
    _write_per_ppa_breakdown(stats["per_ppa"], with_ubuntu=with_ubuntu)
    _write_overlap_section(stats["shared"])


def _load_csv_report_rows(csv_path, is_historical, target_dt):
    """Read a detailed CSV, returning (rows, scanned_series, date_ub_col).

    Rows are (record, ubuntu-date-column) tuples filtered to those that had
    arrived in the PPA by *target_dt* when reporting historically.
    """
    rows = []
    with open(csv_path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        scanned_series = _csv_scanned_series(reader.fieldnames)
        date_ub_col = None
        for col in reader.fieldnames or []:
            if "arrived in Ubuntu" in col:
                date_ub_col = col
        for r in reader:
            if not is_historical or _arrived_by(r.get("Date/Time arrived in PPA"), target_dt):
                rows.append((r, date_ub_col))
    return rows, scanned_series, date_ub_col


def _csv_rel_fn(udata, series, target_dt, is_historical):
    """Return (rel_fn, has_target_series) computing PPA-vs-archive comparison per CSV row."""
    has_target_series = bool(udata.archive) and series in (udata.series_seen or [])

    def _rel_for_row(r, u_col):
        p_ver = r.get("Version in PPA", "unknown")
        if is_historical:
            if has_target_series:
                u_ver, u_date_s = archive_ver_date(udata.archive, r["Package"], series)
                u_date = parse_csv_date(u_date_s)
            else:
                u_ver = _csv_scanned_ubuntu_version(r)
                u_date = parse_csv_date(r.get(u_col)) if u_col else None
            if u_date and u_date <= target_dt:
                return version_rel_str(p_ver, u_ver)
            return "PPA only"
        return r.get("Comparison (PPA vs Archive)") or version_rel_str(p_ver, _csv_scanned_ubuntu_version(r))

    return _rel_for_row, has_target_series


def _write_csv_overall(series, stats):
    """Write the OVERALL METRICS block for a CSV-sourced report."""
    total = stats["total_nk"]
    labels = (
        ("Analyzed PPAs:", stats["analyzed_ppas"], None),
        ("Distinct Non-Kernel Packages:", total, None),
        ("Distinct Kernel Packages:", len(stats["kernel_names"]), None),
        (f"PPA older than Ubuntu ({series}):", stats["older"], "pct"),
        (f"PPA same as Ubuntu ({series}):", stats["same"], "pct"),
        (f"PPA newer than Ubuntu ({series}):", stats["newer"], "pct"),
        (f"PPA only (NOT in Ubuntu {series}):", stats["only"], "pct"),
    )
    sys.stdout.write("\n=== OVERALL METRICS ===\n\n")
    for label, value, kind in labels:
        if kind == "pct":
            pct = (value / total * 100) if total else 0
            sys.stdout.write(f"  {label:<36} {value:>5} ({pct:>5.1f}%)\n")
        else:
            sys.stdout.write(f"  {label:<36} {value:>5}\n")
    if stats["is_historical"]:
        sys.stdout.write(_coverage_metric_line(stats["coverage"]) + "\n")


def _csv_report_doc(series, source, stats):
    """Build the JSON document for a CSV-sourced report."""
    return {
        "tool": APP_NAME,
        "tool_version": TOOL_VERSION,
        "execution_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": stats["mode"],
        "reporting_date": stats["reporting_date"],
        "ubuntu_series": series,
        "source_csv": source,
        "analyzed_ppas": stats["analyzed_ppas"],
        "totals": {
            "non_kernel_distinct": stats["total_nk"],
            "kernel_distinct": len(stats["kernel_names"]),
            "ppa_older": stats["older"], "ppa_same": stats["same"],
            "ppa_newer": stats["newer"], "ppa_only": stats["only"],
        },
        "ubuntu_coverage": stats["coverage"],
        "per_ppa": stats["per_ppa"],
        "package_overlap": stats["shared"],
    }


def _report_from_csv(csv_path, series="stonking", target_date_str="today", as_json=False,
                     udata=None):
    """Format and print statistics loaded from a detailed CSV file as of target_date_str."""
    udata = udata or UbuntuData()
    target_dt = parse_target_date(target_date_str)
    is_historical = target_date_str not in ("today", "latest", None)
    if is_historical and not _has_ubuntu_dates_in_csv(csv_path):
        sys.stderr.write(_NO_UBUNTU_DATES_WARNING)

    rows, scanned_series, _ucol = _load_csv_report_rows(csv_path, is_historical, target_dt)
    rel_fn, has_series = _csv_rel_fn(udata, series, target_dt, is_historical)
    if is_historical and not has_series and scanned_series and series != scanned_series:
        sys.stderr.write(_series_mismatch_note(series, scanned_series))

    stats = _aggregate_csv_items(rows, rel_fn)
    distinct = stats["distinct"]
    stats["older"], stats["same"], stats["newer"], stats["only"] = _rel_counts(distinct.values())
    stats["total_nk"] = len(distinct)
    stats["is_historical"] = is_historical
    stats["mode"] = "historical" if is_historical else "today"
    stats["reporting_date"] = (target_dt.strftime("%Y-%m-%d") if is_historical
                               else datetime.now().strftime("%Y-%m-%d"))
    if has_series:
        stats["coverage"] = archive_date_coverage(sorted(distinct), udata.archive, series)
    else:
        stats["coverage"] = _csv_ubuntu_coverage(csv_path)

    if as_json:
        sys.stdout.write(json.dumps(_csv_report_doc(series, os.path.basename(csv_path), stats),
                                    indent=2) + "\n")
        return

    _write_report_header(f"(Ubuntu Series: {series}, Source: {os.path.basename(csv_path)})",
                         _rep_date_str(is_historical, target_dt))
    _write_csv_overall(series, stats)
    _write_per_ppa_breakdown(stats["per_ppa"])
    _write_overlap_section(stats["shared"])


def get_last_n_quarters(n=4, now_dt=None):
    """Return list of dicts for the last *n* consecutive quarters before now_dt."""
    if now_dt is None:
        now_dt = datetime.now()
    year = now_dt.year
    month = now_dt.month
    curr_q = (month - 1) // 3 + 1
    q_list = []
    y, q = year, curr_q
    for _ in range(max(1, n)):
        q -= 1
        if q < 1:
            q = 4
            y -= 1
        q_list.append((y, q))
    q_list.reverse()

    quarters_info = []
    q_ends = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}
    for y, q in q_list:
        m_end, d_end = q_ends[q]
        end_dt = datetime(y, m_end, d_end, 23, 59, 59)
        quarters_info.append({
            "label": f"{y}Q{q}",
            "end_dt": end_dt,
            "series": get_devel_series_for_date(end_dt),
        })
    return quarters_info


def get_last_4_quarters(now_dt=None):
    """Backwards-compatible wrapper: the last 4 consecutive quarters."""
    return get_last_n_quarters(4, now_dt)


def _quarter_rows(csv_path, end_dt):
    """Read CSV (record, ubuntu-date-column) tuples for packages present by end_dt."""
    rows = []
    with open(csv_path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        date_ub_col = None
        for col in reader.fieldnames or []:
            if "arrived in Ubuntu" in col:
                date_ub_col = col
        for r in reader:
            p_date = parse_csv_date(r.get("Date/Time arrived in PPA"))
            if p_date is None or p_date <= end_dt:
                rows.append((r, date_ub_col))
    return rows


def _quarter_rel_fn(udata, series, end_dt):
    """Return (rel_fn, has_series) computing the as-of-quarter comparison for a row."""
    has_series = bool(udata.archive) and series in (udata.series_seen or [])

    def _rel(r, u_col):
        p_ver = r.get("Version in PPA", "unknown")
        if has_series:
            u_ver, u_date_s = archive_ver_date(udata.archive, r["Package"], series)
            u_date = parse_csv_date(u_date_s)
        else:
            u_ver = _csv_scanned_ubuntu_version(r)
            u_date = parse_csv_date(r.get(u_col)) if u_col else None
        if u_date and u_date <= end_dt:
            return version_rel_str(p_ver, u_ver)
        return "PPA only"

    return _rel, has_series


def _one_quarter_metrics(csv_path, q, udata):
    """Compute one quarter's unique-package statistics from a detailed CSV."""
    end_dt = q["end_dt"]
    series = q["series"]
    rel_fn, has_series = _quarter_rel_fn(udata, series, end_dt)
    rows = _quarter_rows(csv_path, end_dt)
    nk_items = [it for it in rows if it[0]["Type"] == "non-kernel"]
    k_items = [it for it in rows if it[0]["Type"] == "kernel"]
    distinct = {}
    for r, u_col in nk_items:
        distinct.setdefault(r["Package"], rel_fn(r, u_col))
    counts = _rel_counts(distinct.values())
    return {
        "label": q["label"], "series": series,
        "series_source": "archive" if has_series else "csv-approx",
        "end_dt_str": end_dt.strftime("%Y-%m-%d"), "total_nk": len(distinct),
        "c_older": counts[0], "c_same": counts[1], "c_newer": counts[2], "c_only": counts[3],
        "total_k": len({it[0]["Package"] for it in k_items}),
    }


def _quarter_metrics(csv_path, quarters, udata=None):
    """Compute per-quarter unique-package statistics from a detailed CSV.

    When multi-series archive data covers a quarter's development series, that
    series' real archive versions/dates are used; otherwise the CSV's scanned
    single-series columns are used as an approximation.
    """
    udata = udata or UbuntuData()
    return [_one_quarter_metrics(csv_path, q, udata) for q in quarters]


def _quarters_report_doc(csv_path, n, cov, q_metrics):
    """Build the JSON document for the N-quarter trend report."""
    return {
        "tool": APP_NAME,
        "tool_version": TOOL_VERSION,
        "execution_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "last_quarters",
        "quarters_count": n,
        "source_csv": os.path.basename(csv_path),
        "ubuntu_coverage": cov,
        "quarters": [
            {
                "quarter": m["label"],
                "ubuntu_series": m["series"],
                "series_source": m["series_source"],
                "as_of_date": m["end_dt_str"],
                "distinct_non_kernel": m["total_nk"],
                "ppa_older": m["c_older"],
                "ppa_same": m["c_same"],
                "ppa_newer": m["c_newer"],
                "ppa_only": m["c_only"],
                "distinct_kernel": m["total_k"],
            }
            for m in q_metrics
        ],
    }


def _quarters_report_text(csv_path, n, cov, q_metrics):
    """Build the plain-text N-quarter trend report string."""
    hdr = (f"  {'Quarter':<10} | {'Ubuntu Series':<15} | {'Source':<11} | {'Non-Kernel':<10} | "
           f"{'PPA older':<9} | {'PPA same':<8} | {'PPA newer':<9} | {'PPA only':<8} | {'Kernel':<7}")
    lines = [
        "=" * 95,
        "REPORTING PHASE",
        f"(Mode: Last {n} Consecutive Quarters, Source: {os.path.basename(csv_path)})",
        f"Execution date: {datetime.now().strftime('%Y-%m-%d - %H:%M:%S')}",
        (f"Ubuntu arrival-date coverage: {cov['with_arrival_date']}/{cov['available_in_ubuntu']} "
         f"available ({cov['date_coverage_pct_of_available']:.1f}%)"),
        "Series source: 'archive' = multi-series snapshot; 'csv-approx' = scanned-series approximation",
        "Note: Base is always PPA package vs Ubuntu archive (PPA older / same / newer than archive)",
        "=" * 95,
        "",
        f"=== {n}-QUARTER TREND SUMMARY ===",
        "",
        hdr,
        "  " + "-" * (len(hdr) - 2),
    ]
    for m in q_metrics:
        lines.append(f"  {m['label']:<10} | {m['series']:<15} | {m['series_source']:<11} | "
                     f"{m['total_nk']:^10} | {m['c_older']:^9} | {m['c_same']:^8} | "
                     f"{m['c_newer']:^9} | {m['c_only']:^8} | {m['total_k']:^7}")
    lines.append("=" * 95)
    lines.append("")
    return "\n".join(lines) + "\n"


def build_last_quarters_report(csv_path, n=4, outdir=".", write_files=True, as_json=False):
    """Build and print an N-quarter comparison report from a detailed CSV file.

    Loads the latest multi-series archive side-car (if any) from *outdir* so each
    quarter can be compared against its own development series when covered.
    """
    quarters = get_last_n_quarters(n)
    n = len(quarters)
    cov = _csv_ubuntu_coverage(csv_path)

    if not _has_ubuntu_dates_in_csv(csv_path):
        sys.stderr.write(_NO_UBUNTU_DATES_WARNING)

    archive, series_seen = load_latest_archive_map(outdir)
    udata = UbuntuData(archive=archive, series_seen=series_seen)
    q_metrics = _quarter_metrics(csv_path, quarters, udata)

    if as_json:
        out = json.dumps(_quarters_report_doc(csv_path, n, cov, q_metrics), indent=2) + "\n"
        sys.stdout.write(out)
        if write_files:
            report_path = os.path.join(outdir, "pe-ppa-package-report_lastquarters.json")
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write(out)
            sys.stderr.write(f"Wrote quarterly JSON report: {report_path}\n")
        return out

    out = _quarters_report_text(csv_path, n, cov, q_metrics)
    sys.stdout.write(out)
    if write_files:
        report_path = os.path.join(outdir, "pe-ppa-package-report_lastquarters.txt")
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(out)
        sys.stderr.write(f"Wrote quarterly report: {report_path}\n")
    return out


def run_report_phase(args, results=None, ubuntu_info=None):
    """Calculate and print statistics for analyzed PPA data."""
    csv_files = sorted(glob.glob(os.path.join(args.outdir, "pe-ppa-package-details_*.csv")))
    latest_csv = csv_files[-1] if csv_files else None
    as_json = bool(getattr(args, "json", False))
    archive, series_seen = load_latest_archive_map(args.outdir)

    if getattr(args, "lastyear", False):
        if not latest_csv:
            sys.exit("ERROR: no scan data files found in " + os.path.abspath(args.outdir) + " for --lastyear report.")
        sys.stderr.write(f"Loading report data for quarterly report from CSV: {latest_csv}\n")
        return build_last_quarters_report(
            latest_csv, n=getattr(args, "quarters_n", 4),
            outdir=args.outdir, write_files=not args.no_files, as_json=as_json)

    target_date_str = getattr(args, "report", "today") or "today"
    target_dt = parse_target_date(target_date_str)

    if getattr(args, "ubuntu_series", None):
        series = args.ubuntu_series
    else:
        series = get_devel_series_for_date(target_dt)

    scan_series = str(getattr(args, "ubuntu_series", None)
                      or get_devel_series_for_date(datetime.now()) or "stonking")

    if results is not None:
        udata = UbuntuData(info=ubuntu_info, archive=archive,
                           series_seen=series_seen, scan_series=scan_series)
        return _report_from_in_memory(results, series=series,
                                      target_date_str=target_date_str, as_json=as_json, udata=udata)

    if not latest_csv:
        sys.exit("ERROR: no scan data files found in " + os.path.abspath(args.outdir) + " for report phase.")
    sys.stderr.write(f"Loading report data from latest CSV: {latest_csv}\n")
    udata = UbuntuData(archive=archive, series_seen=series_seen, scan_series=scan_series)
    return _report_from_csv(latest_csv, series=series,
                            target_date_str=target_date_str, as_json=as_json, udata=udata)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _exit_code(skipped):
    """Map skipped PPAs to a process exit code (archived skips are not failures)."""
    if any(reason != "archived" for _, reason in skipped):
        return EXIT_PARTIAL
    return EXIT_OK


def render_and_write(args, results, skipped, now=None, lp=None, ubuntu_info=None):
    """Render results (table or JSON) to stdout and optionally write the files."""
    table_str, tot_nk, tot_k = build_table(results)
    series = str(getattr(args, "ubuntu_series", None) or get_devel_series_for_date(datetime.now()) or "stonking")
    ubuntu_source = "local-csv" if getattr(args, "test", False) else "none"
    archive_map = {}

    if ubuntu_info is None and not getattr(args, "no_ubuntu_check", False):
        all_nk = sorted({pkg for r in results for pkg in r["nonkernel"]})
        sys.stderr.write(
            f"Checking Ubuntu archive ({series}) availability for {len(all_nk)} non-kernel packages...\n"
        )
        meta_holder = {}
        ubuntu_info = check_ubuntu_availability(all_nk, series=series, lp=lp, meta=meta_holder)
        ubuntu_source = meta_holder.get("ubuntu_source", "none")
        archive_map = meta_holder.get("archive_map") or {}

    if args.json:
        json.dump(build_json(results, skipped, args, ubuntu_info=ubuntu_info), sys.stdout, indent=2)
        sys.stdout.write("\n")
        notes = sys.stderr
    else:
        print(table_str)
        print(f"\nTOTAL unique non-kernel packages: {tot_nk}  |  kernel-related: {tot_k}")
        if args.global_unique:
            g_nk, g_k = global_unique_counts(results)
            print(f"Distinct across ALL PPAs (each counted once): {g_nk} non-kernel  |  kernel-related: {g_k}")
        if ubuntu_info:
            all_nk = sorted({pkg for r in results for pkg in r["nonkernel"]})
            avail_count = sum(1 for p in all_nk if ubuntu_info.get(p, {}).get("available"))
            print(f"In Ubuntu {series}: {avail_count}/{len(all_nk)} distinct non-kernel packages")
        notes = sys.stdout

    if not args.no_files:
        os.makedirs(args.outdir, exist_ok=True)
        csv_details_name, meta_name, archive_name, txt_name = get_output_filenames(now=now)
        csv_details_path = os.path.join(args.outdir, csv_details_name)
        meta_path = os.path.join(args.outdir, meta_name)
        archive_path = os.path.join(args.outdir, archive_name)
        txt_path = os.path.join(args.outdir, txt_name)
        write_details_csv(csv_details_path, results, ubuntu_info=ubuntu_info, series=series)
        write_scan_meta(meta_path, build_scan_meta(
            results, skipped, ubuntu_info, series, ubuntu_source, args, archive_map=archive_map))
        wrote = [csv_details_path, meta_path]
        if archive_map:
            write_archive_map(archive_path, archive_map, series)
            wrote.append(archive_path)
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write(build_txt(results, skipped, table_str, args, ubuntu_info=ubuntu_info))
        wrote.append(txt_path)
        print("\nWrote: " + "\n       ".join(wrote), file=notes)

    return ubuntu_info


def load_local_scan_results(outdir="."):
    """Load local scan data from the latest pe-ppa-package-details_*.csv file.

    Returns (results, ubuntu_info, latest_csv_path).
    Raises FileNotFoundError if no local CSV file is found.
    """
    pattern = os.path.join(outdir, "pe-ppa-package-details_*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"no local scan CSV files found in '{os.path.abspath(outdir)}'")

    latest_csv = files[-1]
    results_dict = {}
    ubuntu_info = {}

    with open(latest_csv, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        ver_col = None
        date_col = None
        for col in reader.fieldnames or []:
            if col.startswith("Version in ") and col != "Version in PPA":
                ver_col = col
            if col.startswith("Date/Time arrived in Ubuntu") or col.startswith("Date/Time arrived in "):
                if "PPA" not in col:
                    date_col = col

        for r in reader:
            spec = r["PPA"]
            pkg = r["Package"]
            p_type = r["Type"]
            p_ver = r.get("Version in PPA", "unknown")
            p_date = r.get("Date/Time arrived in PPA", "none")

            if spec not in results_dict:
                results_dict[spec] = {
                    "spec": spec,
                    "label": spec,
                    "private": "(private)" in spec.lower(),
                    "archived": "(archived)" in spec.lower(),
                    "nonkernel": [],
                    "kernel": [],
                    "borderline": [],
                    "versions": {},
                    "dates": {},
                }

            entry = results_dict[spec]
            entry["versions"][pkg] = p_ver
            entry["dates"][pkg] = p_date
            if p_type == "kernel":
                entry["kernel"].append(pkg)
            else:
                entry["nonkernel"].append(pkg)
                if ver_col and ver_col in r:
                    u_ver = r[ver_col]
                    u_date = r.get(date_col) if date_col else None
                    avail = u_ver not in ("none", "N/A", "", None)
                    ubuntu_info[pkg] = {
                        "available": avail,
                        "version": u_ver if avail else None,
                        "date_published": u_date if avail else None,
                        "component": "main" if avail else None,
                    }

    results = list(results_dict.values())
    for r in results:
        r["borderline"] = [n for n in r["nonkernel"] if BORDERLINE_RE.search(n)]

    return results, ubuntu_info, latest_csv


def main(argv):
    """Run the scan and/or report phases based on command line flags."""
    args = parse_args(argv)

    run_scan = args.scan or args.all or (not args.scan and not args.report and not args.all)
    run_report = bool(args.report) or args.lastyear or args.all or (not args.scan and not args.report and not args.all)

    results = None
    skipped = []
    ubuntu_info = None

    if run_scan:
        scan_series = getattr(args, "ubuntu_series", None) or get_devel_series_for_date(datetime.now()) or "stonking"
        exec_date = datetime.now().strftime("%Y-%m-%d - %H:%M:%S")
        sys.stdout.write("\n" + "=" * 95 + "\n")
        sys.stdout.write("GATHERING PHASE\n")
        sys.stdout.write(f"(Ubuntu Series: {scan_series})\n")
        sys.stdout.write(f"Execution date: {exec_date}\n")
        sys.stdout.write("=" * 95 + "\n\n")

        if args.test:
            try:
                results, local_ub_info, latest_csv = load_local_scan_results(args.outdir)
                csv_filename = os.path.basename(latest_csv)
                sys.stderr.write(
                    f"Started in test mode, using last CSV file content ({csv_filename}) as input, not scanning Launchpad for latest data.\n"
                )
                if not args.no_ubuntu_check and local_ub_info:
                    ubuntu_info = local_ub_info
            except FileNotFoundError as exc:
                sys.exit(f"ERROR: {exc}")
        else:
            raw = args.ppas.split(",") if args.ppas else DEFAULT_PPAS
            try:
                specs = [normalize_ppa(s) for s in raw if s.strip()]
            except ValueError as exc:
                sys.exit(f"ERROR: {exc}")
            if not specs:
                sys.exit("ERROR: no PPAs to analyze")

            lp = login(args)
            results, skipped = analyze(lp, specs, args.include_archived)
            if not results:
                sys.stderr.write("No PPAs could be analyzed.\n")
                return EXIT_NO_RESULTS

        ubuntu_info = render_and_write(args, results, skipped, lp=None if args.test else lp, ubuntu_info=ubuntu_info)

    if run_report:
        run_report_phase(args, results=results, ubuntu_info=ubuntu_info)

    return _exit_code(skipped)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
