#!/usr/bin/python3
"""Unit tests for pe_ppa_package_stats.py.

These exercise the pure logic (kernel filtering, PPA-spec parsing, table/JSON
rendering, global-unique counting, exit codes) using small fakes in place of
launchpadlib, so the tests need no network access. Importing the module is
side-effect free because all program flow lives under main()/__main__.

Run with either:
    python3 -m unittest test_pe_ppa_package_stats -v
    python3 test_pe_ppa_package_stats.py
"""

# The fixture classes deliberately mirror launchpadlib's camelCase API and are
# self-descriptive, and a few tests reach into module-private helpers on purpose.
# pylint: disable=missing-class-docstring, missing-function-docstring, too-few-public-methods, invalid-name, protected-access

import io
import json
import unittest
from contextlib import redirect_stderr

import pe_ppa_package_stats as pps


# --- Fakes standing in for launchpadlib objects ----------------------------
class FakePub:
    def __init__(self, name, version="1.0-1"):
        self.source_package_name = name
        self.source_package_version = version


class FakeArchive:
    def __init__(self, displayname="Test PPA", private=False, names=()):
        self.displayname = displayname
        self.private = private
        self._names = list(names)

    def getPublishedSources(self, **_kwargs):
        return [FakePub(n) for n in self._names]


class FakeArchives:
    def __init__(self, mapping):
        self._mapping = mapping

    def getByReference(self, reference):
        return self._mapping.get(reference)


class FakeLP:
    def __init__(self, mapping):
        self.archives = FakeArchives(mapping)


def make_lp(specs_to_archive):
    """Build a FakeLP keyed by the ~owner/ubuntu/archive references."""
    mapping = {}
    for spec, archive in specs_to_archive.items():
        owner, name = spec.split("/", 1)
        mapping[f"~{owner}/ubuntu/{name}"] = archive
    return FakeLP(mapping)


def analyze_quiet(lp, specs, include_archived=False):
    """Run pps.analyze with stderr (progress/warnings) suppressed."""
    with redirect_stderr(io.StringIO()):
        return pps.analyze(lp, specs, include_archived)


class KernelRegexTests(unittest.TestCase):
    def test_kernel_names_match(self):
        for name in ("linux", "linux-foo", "linux-meta-nvidia-6.17",
                     "flash-kernel", "flash-kernel-tools"):
            self.assertTrue(pps.KERNEL_RE.match(name), name)

    def test_non_kernel_names_do_not_match(self):
        for name in ("linuxfoo", "flash-kernelish", "nvidia-graphics-drivers-580",
                     "gstreamer", "xilinx-vcu-modules"):
            self.assertIsNone(pps.KERNEL_RE.match(name), name)


class NormalizePpaTests(unittest.TestCase):
    def test_owner_archive(self):
        self.assertEqual(pps.normalize_ppa("me/ppa"), "me/ppa")

    def test_tilde_prefix(self):
        self.assertEqual(pps.normalize_ppa("~me/ppa"), "me/ppa")

    def test_reference_form(self):
        self.assertEqual(pps.normalize_ppa("~me/ubuntu/ppa"), "me/ppa")

    def test_full_url(self):
        url = "https://launchpad.net/~me/+archive/ubuntu/ppa"
        self.assertEqual(pps.normalize_ppa(url), "me/ppa")

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            pps.normalize_ppa("not-a-valid-ppa-spec")


class AnalyzeTests(unittest.TestCase):
    def test_kernel_split_and_dedup(self):
        lp = make_lp({"me/ppa": FakeArchive(
            names=["alpha", "alpha", "linux-foo", "flash-kernel", "beta"])})
        results, skipped = analyze_quiet(lp, ["me/ppa"])
        self.assertEqual(skipped, [])
        r = results[0]
        self.assertEqual(r["nonkernel"], ["alpha", "beta"])
        self.assertEqual(r["kernel"], ["flash-kernel", "linux-foo"])

    def test_archived_skipped_by_default(self):
        lp = make_lp({"me/old": FakeArchive(
            displayname="Old PPA (archived)", names=["x"])})
        results, skipped = analyze_quiet(lp, ["me/old"])
        self.assertEqual(results, [])
        self.assertEqual(skipped, [("me/old", "archived")])

    def test_archived_included_when_requested(self):
        lp = make_lp({"me/old": FakeArchive(
            displayname="Old PPA (archived)", names=["x"])})
        results, skipped = analyze_quiet(lp, ["me/old"], include_archived=True)
        self.assertEqual(skipped, [])
        self.assertTrue(results[0]["archived"])
        self.assertIn("(archived)", results[0]["label"])

    def test_not_found_is_skipped(self):
        lp = make_lp({})  # getByReference returns None for any reference
        results, skipped = analyze_quiet(lp, ["me/ghost"])
        self.assertEqual(results, [])
        self.assertEqual(skipped, [("me/ghost", "not found or no access")])

    def test_private_label_and_borderline(self):
        lp = make_lp({"me/p": FakeArchive(
            private=True,
            names=["nvidia-graphics-drivers-580", "foo-modules", "bar"])})
        results, _ = analyze_quiet(lp, ["me/p"])
        r = results[0]
        self.assertTrue(r["private"])
        self.assertIn("(private)", r["label"])
        self.assertEqual(r["borderline"],
                         ["foo-modules", "nvidia-graphics-drivers-580"])


class GlobalUniqueTests(unittest.TestCase):
    def test_dedup_across_ppas(self):
        lp = make_lp({
            "a/one": FakeArchive(names=["shared", "a-only", "linux-x"]),
            "b/two": FakeArchive(names=["shared", "b-only"]),
        })
        results, _ = analyze_quiet(lp, ["a/one", "b/two"])
        _, tot_nk, tot_k = pps.build_table(results)
        self.assertEqual((tot_nk, tot_k), (4, 1))          # additive
        self.assertEqual(pps.global_unique_counts(results), (3, 1))  # distinct


class BuildTableTests(unittest.TestCase):
    def test_totals_and_rectangular_shape(self):
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, _ = analyze_quiet(lp, ["me/ppa"])
        table, tot_nk, tot_k = pps.build_table(results)
        self.assertEqual((tot_nk, tot_k), (2, 1))
        self.assertIn("Non-kernel", table)
        self.assertIn("Kernel", table)
        self.assertNotIn("Kernel package names", table)
        self.assertIn("TOTAL", table)
        lines = table.splitlines()
        self.assertTrue(all(len(ln) == len(lines[0]) for ln in lines))


class ExitCodeTests(unittest.TestCase):
    def test_clean_run_is_ok(self):
        self.assertEqual(pps._exit_code([]), pps.EXIT_OK)

    def test_archived_only_is_ok(self):
        self.assertEqual(pps._exit_code([("me/old", "archived")]), pps.EXIT_OK)

    def test_other_skip_is_partial(self):
        self.assertEqual(
            pps._exit_code([("me/x", "not found or no access")]), pps.EXIT_PARTIAL)


class BuildJsonTests(unittest.TestCase):
    def test_structure_and_serializable(self):
        lp = make_lp({
            "a/one": FakeArchive(names=["shared", "a-only", "linux-x"]),
            "b/two": FakeArchive(names=["shared", "b-only"]),
        })
        results, skipped = analyze_quiet(lp, ["a/one", "b/two"])
        args = pps.parse_args(["tester"])
        doc = pps.build_json(results, skipped, args)
        self.assertEqual(doc["auth_mode"], "authenticated")
        self.assertEqual(doc["lp_user"], "tester")
        self.assertEqual(len(doc["ppas"]), 2)
        self.assertEqual(doc["totals"]["non_kernel_additive"], 4)
        self.assertEqual(doc["totals"]["non_kernel_distinct_across_ppas"], 3)
        # round-trips cleanly through the json module
        self.assertEqual(
            json.loads(json.dumps(doc))["totals"]["kernel_additive"], 1)


class BuildTxtTests(unittest.TestCase):
    def test_sections_present(self):
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, skipped = analyze_quiet(lp, ["me/ppa"])
        args = pps.parse_args(["tester"])
        table, _, _ = pps.build_table(results)
        txt = pps.build_txt(results, skipped, table, args)
        for marker in ("SUMMARY TABLE", "FULL PACKAGE LISTS", "NOTES",
                       "Distinct across ALL PPAs",
                       "Non-kernel packages:", "Kernel-related packages:"):
            self.assertIn(marker, txt)
        self.assertIn("a", txt)
        self.assertIn("b", txt)
        self.assertIn("linux-z", txt)
        self.assertTrue(txt.endswith("\n"))


class WriteCsvTests(unittest.TestCase):
    def test_write_details_csv(self):
        import tempfile
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, _ = analyze_quiet(lp, ["me/ppa"])
        ubuntu_info = {"a": {"available": True, "version": "2.0", "date_published": "2026-01-01 10:00:00"}, "b": {"available": False}}
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".csv") as tmp:
            pps.write_details_csv(tmp.name, results, ubuntu_info=ubuntu_info)
            tmp.seek(0)
            with open(tmp.name, "r", encoding="utf-8") as fh:
                content = fh.read()
        self.assertIn("Package,Type,Version in PPA,Date/Time arrived in PPA,Version in Ubuntu stonking,Date/Time arrived in Ubuntu stonking,Comparison (PPA vs Archive)", content)
        self.assertIn("me/ppa,a,non-kernel,1.0-1,none,2.0,2026-01-01 10:00:00,PPA older", content)
        self.assertIn("me/ppa,b,non-kernel,1.0-1,none,none,none,PPA only", content)
        self.assertIn("me/ppa,linux-z,kernel,1.0-1,none,N/A,N/A,N/A", content)


class OutputFilenamesTests(unittest.TestCase):
    def test_timestamp_formatting(self):
        from datetime import datetime
        dt = datetime(2026, 8, 10, 14, 23, 45)
        csv_details_fn, meta_fn, archive_fn, txt_fn = pps.get_output_filenames(now=dt)
        self.assertEqual(csv_details_fn, "pe-ppa-package-details_20260810_14:23:45.csv")
        self.assertEqual(meta_fn, "pe-ppa-package-meta_20260810_14:23:45.json")
        self.assertEqual(archive_fn, "pe-ppa-package-archive_20260810_14:23:45.json")
        self.assertEqual(txt_fn, "pe-ppa-package-counts_20260810_14:23:45.txt")


class CheckUbuntuAvailabilityTests(unittest.TestCase):
    def test_empty_packages(self):
        res = pps.check_ubuntu_availability([], series="stonking")
        self.assertEqual(res, {})

    def test_fallback_chain(self):
        from unittest.mock import patch
        with patch.object(pps, "_check_ubuntu_via_launchpadlib", side_effect=RuntimeError("lplib fail")):
            with patch.object(pps, "_check_ubuntu_via_rmadison_cli", return_value={"pkg": {"available": True, "version": "1.0", "component": "main"}}) as mock_cli:
                with redirect_stderr(io.StringIO()):
                    res = pps.check_ubuntu_availability(["pkg"], series="stonking")
                self.assertTrue(res["pkg"]["available"])
                mock_cli.assert_called_once()

    def test_fallback_to_web_madison(self):
        from unittest.mock import patch
        with patch.object(pps, "_check_ubuntu_via_launchpadlib", side_effect=RuntimeError("lplib fail")):
            with patch.object(pps, "_check_ubuntu_via_rmadison_cli", side_effect=RuntimeError("cli fail")):
                with patch.object(pps, "_check_ubuntu_via_web_madison", return_value={"pkg": {"available": True, "version": "2.0", "component": "main"}}) as mock_web:
                    with redirect_stderr(io.StringIO()):
                        res = pps.check_ubuntu_availability(["pkg"], series="stonking")
                    self.assertTrue(res["pkg"]["available"])
                    mock_web.assert_called_once()

    def test_version_comparison_logic(self):
        self.assertEqual(pps.version_rel_str("1.0", "2.0"), "PPA older")
        self.assertEqual(pps.version_rel_str("2.0", "2.0"), "PPA same")
        self.assertEqual(pps.version_rel_str("2.0", "1.0"), "PPA newer")
        self.assertEqual(pps.version_rel_str("1.0", "none"), "PPA only")

    def test_with_ubuntu_info_in_reports(self):
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, skipped = analyze_quiet(lp, ["me/ppa"])
        args = pps.parse_args(["tester"])
        ubuntu_info = {
            "a": {"available": True, "version": "1.0-1", "component": "main"},
            "b": {"available": False, "version": None, "component": None},
        }
        table, _, _ = pps.build_table(results)
        txt = pps.build_txt(results, skipped, table, args, ubuntu_info=ubuntu_info)
        self.assertIn("UBUNTU ARCHIVE AVAILABILITY (series: stonking)", txt)
        self.assertIn("a  (PPA: 1.0-1 | stonking: 1.0-1 [PPA same])", txt)
        self.assertIn("b  (PPA: 1.0-1 | stonking: none [PPA only])", txt)


class PhaseFlagsAndReportTests(unittest.TestCase):
    def test_cli_phase_flags(self):
        a_default = pps.parse_args(["tester"])
        self.assertTrue(a_default.all)

        a_scan = pps.parse_args(["tester", "--scan"])
        self.assertTrue(a_scan.scan)
        self.assertFalse(a_scan.report)

        a_report = pps.parse_args(["--report"])
        self.assertTrue(a_report.report)
        self.assertFalse(a_report.scan)

        a_all = pps.parse_args(["tester", "-a"])
        self.assertTrue(a_all.all)

        a_test = pps.parse_args(["-t"])
        self.assertTrue(a_test.test)

        a_test_long = pps.parse_args(["--test", "--scan"])
        self.assertTrue(a_test_long.test)
        self.assertTrue(a_test_long.scan)

    def test_lastyear_flag(self):
        a_ly = pps.parse_args(["--lastyear"])
        self.assertTrue(a_ly.lastyear)
        self.assertEqual(a_ly.report, "lastyear")

    def test_load_local_scan_results(self):
        import os
        import tempfile
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, _ = analyze_quiet(lp, ["me/ppa"])
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            pps.write_details_csv(csv_path, results)
            loaded, _, path = pps.load_local_scan_results(tmpdir)
            self.assertEqual(path, csv_path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["nonkernel"], ["a", "b"])
            self.assertEqual(loaded[0]["kernel"], ["linux-z"])

    def test_run_report_phase_in_memory(self):
        from contextlib import redirect_stdout
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, _ = analyze_quiet(lp, ["me/ppa"])
        args = pps.parse_args(["tester", "--report"])
        ubuntu_info = {"a": {"available": True, "version": "1.0"}, "b": {"available": False}}
        with io.StringIO() as buf, redirect_stderr(io.StringIO()):
            with redirect_stdout(buf):
                pps.run_report_phase(args, results=results, ubuntu_info=ubuntu_info)
            out = buf.getvalue()
        self.assertIn("REPORTING PHASE", out)
        self.assertIn("Execution date:", out)
        self.assertIn("Reporting date:", out)
        self.assertIn("Distinct Non-Kernel Packages:", out)

    def test_get_current_devel_series(self):
        series = pps.get_current_devel_series()
        self.assertTrue(isinstance(series, str))
        self.assertTrue(len(series) > 0)

    def test_parse_target_date(self):
        dt1 = pps.parse_target_date("20260101")
        self.assertEqual(dt1.year, 2026)
        self.assertEqual(dt1.month, 1)
        self.assertEqual(dt1.day, 1)

    def test_run_report_phase_historical(self):
        from contextlib import redirect_stdout
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, _ = analyze_quiet(lp, ["me/ppa"])
        args = pps.parse_args(["tester", "-r=20260101"])
        ubuntu_info = {"a": {"available": True, "version": "1.0", "date_published": "2026-06-01 12:00:00"}}
        with io.StringIO() as buf, redirect_stderr(io.StringIO()):
            with redirect_stdout(buf):
                pps.run_report_phase(args, results=results, ubuntu_info=ubuntu_info)
            out = buf.getvalue()
        self.assertIn("Execution date:", out)
        self.assertIn("Reporting date: 2026-01-01", out)

    def test_quarterly_deduplication(self):
        import csv
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA", "Version in Ubuntu stonking", "Date/Time arrived in Ubuntu stonking", "Comparison (PPA vs Archive)"])
                w.writerow(["ppa1", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00", "2.0", "2025-02-01 10:00:00", "PPA older"])
                w.writerow(["ppa2", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00", "2.0", "2025-02-01 10:00:00", "PPA older"])
                w.writerow(["ppa1", "pkg-b", "non-kernel", "1.0", "2025-01-01 10:00:00", "none", "none", "PPA only"])

            with io.StringIO() as buf, redirect_stderr(io.StringIO()):
                with redirect_stdout(buf):
                    pps.build_last_quarters_report(csv_path, outdir=tmpdir, write_files=False)
                out = buf.getvalue()
            self.assertIn("TREND SUMMARY", out)

    def test_missing_ubuntu_dates_detection_and_warning(self):
        import csv
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            # CSV with NO Ubuntu arrival dates (fallback-scan style).
            no_dates = os.path.join(tmpdir, "pe-ppa-package-details_20260101_000000.csv")
            with open(no_dates, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA", "Version in Ubuntu stonking", "Date/Time arrived in Ubuntu stonking", "Comparison (PPA vs Archive)"])
                w.writerow(["ppa1", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00", "2.0", "none", "PPA older"])
            self.assertFalse(pps._has_ubuntu_dates_in_csv(no_dates))

            # CSV WITH an Ubuntu arrival date.
            with_dates = os.path.join(tmpdir, "pe-ppa-package-details_20260102_000000.csv")
            with open(with_dates, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA", "Version in Ubuntu stonking", "Date/Time arrived in Ubuntu stonking", "Comparison (PPA vs Archive)"])
                w.writerow(["ppa1", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00", "2.0", "2025-02-01 10:00:00", "PPA older"])
            self.assertTrue(pps._has_ubuntu_dates_in_csv(with_dates))

            # A --lastyear report over the date-less CSV must emit the warning.
            err = io.StringIO()
            with redirect_stderr(err):
                with io.StringIO() as buf, redirect_stdout(buf):
                    pps.build_last_quarters_report(no_dates, outdir=tmpdir, write_files=False)
            self.assertIn("no 'arrived in Ubuntu' dates", err.getvalue())

    def test_has_ubuntu_dates_in_info(self):
        self.assertFalse(pps._has_ubuntu_dates_in_info({}))
        self.assertFalse(pps._has_ubuntu_dates_in_info(
            {"a": {"available": True, "date_published": None}}))
        self.assertTrue(pps._has_ubuntu_dates_in_info(
            {"a": {"available": True, "date_published": "2026-01-01 10:00:00"}}))

    def test_last_n_quarters_flag(self):
        a = pps.parse_args(["--last-n-quarters", "8"])
        self.assertTrue(a.lastyear)
        self.assertEqual(a.quarters_n, 8)
        a2 = pps.parse_args(["--lastyear"])
        self.assertEqual(a2.quarters_n, 4)

    def test_get_last_n_quarters(self):
        from datetime import datetime
        qs = pps.get_last_n_quarters(4, now_dt=datetime(2026, 8, 17))
        self.assertEqual([q["label"] for q in qs],
                         ["2025Q3", "2025Q4", "2026Q1", "2026Q2"])
        self.assertEqual(len(pps.get_last_n_quarters(6, now_dt=datetime(2026, 8, 17))), 6)

    def test_ubuntu_date_coverage(self):
        all_nk = ["a", "b", "c"]
        info = {
            "a": {"available": True, "date_published": "2026-01-01 10:00:00"},
            "b": {"available": True, "date_published": None},   # available, no date
            "c": {"available": False, "date_published": None},  # not in archive
        }
        cov = pps.ubuntu_date_coverage(all_nk, info)
        self.assertEqual(cov["distinct_non_kernel"], 3)
        self.assertEqual(cov["available_in_ubuntu"], 2)
        self.assertEqual(cov["with_arrival_date"], 1)
        self.assertEqual(cov["date_coverage_pct_of_available"], 50.0)

    def test_partial_fallback_merge_and_source(self):
        from unittest.mock import patch
        # Primary returns partial results with one failed package; fallback recovers it.
        primary = ({"a": {"available": True, "version": "1", "date_published": "2026-01-01 00:00:00", "component": "main"},
                    "b": {"available": False, "version": None, "date_published": None, "component": None}},
                   ["b"],
                   {"a": {"stonking": {"version": "1", "date": "2026-01-01 00:00:00"}}})
        with patch.object(pps, "_check_ubuntu_via_launchpadlib", return_value=primary):
            with patch.object(pps, "_check_ubuntu_via_rmadison_cli",
                              return_value={"b": {"available": True, "version": "2", "date_published": None, "component": "universe"}}):
                meta = {}
                with redirect_stderr(io.StringIO()):
                    res = pps.check_ubuntu_availability(["a", "b"], series="stonking", meta=meta)
                self.assertTrue(res["b"]["available"])       # recovered via fallback
                self.assertEqual(res["a"]["date_published"], "2026-01-01 00:00:00")
                self.assertEqual(meta["ubuntu_source"], "launchpad-api+partial-fallback")

    def test_scan_meta_structure(self):
        lp = make_lp({"me/ppa": FakeArchive(names=["a", "b", "linux-z"])})
        results, skipped = analyze_quiet(lp, ["me/ppa"])
        args = pps.parse_args(["tester"])
        ubuntu_info = {"a": {"available": True, "version": "2.0", "date_published": "2026-01-01 10:00:00"},
                       "b": {"available": False, "version": None, "date_published": None}}
        meta = pps.build_scan_meta(results, skipped, ubuntu_info, "stonking", "launchpad-api", args)
        self.assertEqual(meta["tool"], "pe-ppa-package-stats")
        self.assertEqual(meta["ubuntu_source"], "launchpad-api")
        self.assertEqual(meta["ubuntu_series"], "stonking")
        self.assertEqual(meta["ubuntu_coverage"]["with_arrival_date"], 1)

    def test_report_json_output(self):
        import csv
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA", "Version in Ubuntu stonking", "Date/Time arrived in Ubuntu stonking", "Comparison (PPA vs Archive)"])
                w.writerow(["ppa1", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00", "2.0", "2025-02-01 10:00:00", "PPA older"])
                w.writerow(["ppa1", "linux-x", "kernel", "1.0", "2025-01-01 10:00:00", "N/A", "N/A", "N/A"])
            # today JSON via CSV path
            with io.StringIO() as buf, redirect_stderr(io.StringIO()):
                with redirect_stdout(buf):
                    pps._report_from_csv(csv_path, series="stonking", target_date_str="today", as_json=True)
                doc = json.loads(buf.getvalue())
            self.assertEqual(doc["mode"], "today")
            self.assertEqual(doc["totals"]["ppa_older"], 1)
            self.assertIn("ubuntu_coverage", doc)
            self.assertEqual(len(doc["per_ppa"]), 1)

    def test_lastyear_json_output(self):
        import csv
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA", "Version in Ubuntu stonking", "Date/Time arrived in Ubuntu stonking", "Comparison (PPA vs Archive)"])
                w.writerow(["ppa1", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00", "2.0", "2025-02-01 10:00:00", "PPA older"])
            with io.StringIO() as buf, redirect_stderr(io.StringIO()):
                with redirect_stdout(buf):
                    pps.build_last_quarters_report(csv_path, n=4, outdir=tmpdir, write_files=False, as_json=True)
                doc = json.loads(buf.getvalue())
            self.assertEqual(doc["mode"], "last_quarters")
            self.assertEqual(doc["quarters_count"], 4)
            self.assertIn("ubuntu_coverage", doc)


class ArchiveSidecarTests(unittest.TestCase):
    ARCHIVE = {
        "pkg-a": {
            "stonking": {"version": "2.0", "date": "2025-02-01 10:00:00"},
            "questing": {"version": "1.5", "date": "2025-01-15 10:00:00"},
        }
    }

    def _write_csv(self, path):
        import csv
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["PPA", "Package", "Type", "Version in PPA", "Date/Time arrived in PPA",
                        "Version in Ubuntu stonking", "Date/Time arrived in Ubuntu stonking",
                        "Comparison (PPA vs Archive)"])
            w.writerow(["ppa1", "pkg-a", "non-kernel", "1.0", "2025-01-01 10:00:00",
                        "2.0", "2025-02-01 10:00:00", "PPA older"])

    def test_write_and_load_archive_roundtrip(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "pe-ppa-package-archive_20260810_120000.json")
            pps.write_archive_map(path, self.ARCHIVE, "stonking")
            packages, series_seen = pps.load_latest_archive_map(tmpdir)
            self.assertEqual(packages, self.ARCHIVE)
            self.assertEqual(set(series_seen), {"stonking", "questing"})
            self.assertEqual(pps.archive_ver_date(packages, "pkg-a", "questing"),
                             ("1.5", "2025-01-15 10:00:00"))

    def test_report_uses_archive_snapshot_for_covered_series(self):
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            self._write_csv(csv_path)
            udata = pps.UbuntuData(archive=self.ARCHIVE,
                                   series_seen=["stonking", "questing"], scan_series="stonking")
            err = io.StringIO()
            with io.StringIO() as buf, redirect_stderr(err):
                with redirect_stdout(buf):
                    pps._report_from_csv(csv_path, series="questing",
                                         target_date_str="20250601", as_json=True, udata=udata)
                doc = json.loads(buf.getvalue())
            # questing is covered by the archive snapshot -> no mismatch note.
            self.assertNotIn("series", err.getvalue().lower().replace("ubuntu series", ""))
            self.assertEqual(doc["ubuntu_series"], "questing")
            self.assertEqual(doc["totals"]["ppa_older"], 1)

    def test_series_mismatch_note_when_uncovered(self):
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            self._write_csv(csv_path)
            udata = pps.UbuntuData(archive={}, series_seen=[], scan_series="stonking")
            err = io.StringIO()
            with io.StringIO() as buf, redirect_stderr(err):
                with redirect_stdout(buf):
                    pps._report_from_csv(csv_path, series="questing",
                                         target_date_str="20250601", as_json=True, udata=udata)
                doc = json.loads(buf.getvalue())
            self.assertIn("differs from the scanned archive", err.getvalue())
            # Falls back to the scanned-series columns as an approximation.
            self.assertEqual(doc["totals"]["ppa_older"], 1)

    def test_quarterly_source_marks_archive_when_covered(self):
        import os
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "pe-ppa-package-details_20260810_120000.csv")
            self._write_csv(csv_path)
            # Cover every quarter's series so all rows are marked 'archive'.
            all_series = [s[0] for s in pps.UBUNTU_SERIES_TIMELINE]
            archive = {"pkg-a": {s: {"version": "2.0", "date": "2025-02-01 10:00:00"}
                                 for s in all_series}}
            pps.write_archive_map(
                os.path.join(tmpdir, "pe-ppa-package-archive_20260810_120000.json"),
                archive, "stonking")
            with io.StringIO() as buf, redirect_stderr(io.StringIO()):
                with redirect_stdout(buf):
                    pps.build_last_quarters_report(csv_path, n=4, outdir=tmpdir,
                                                   write_files=False, as_json=True)
                doc = json.loads(buf.getvalue())
            self.assertTrue(all(q["series_source"] == "archive" for q in doc["quarters"]))


if __name__ == "__main__":
    unittest.main()
