from pathlib import Path
import csv
import os
import stat
import tempfile
import unittest

from attack_resources.tcp.code.routes import _config_from_request
from attack_resources.tcp.code.tcp_censor_scan.config import MULTI_PROBE_METHODS, ScanConfig, repo_root
from attack_resources.tcp.code.tcp_censor_scan.legacy_scripts.process_test_3 import process_csv_optimized
from attack_resources.tcp.code.tcp_censor_scan.runner import preflight_check


class TcpCensorRouteConfigTests(unittest.TestCase):
    def test_config_from_request_uses_vendored_zmap_roots(self):
        cfg = _config_from_request({"pkt_method": "PSH"})

        self.assertEqual(cfg.zmap_root, repo_root() / "vendor" / "weaponizing-censors" / "zmap")
        self.assertEqual(
            cfg.zmap_multiple_probes_root,
            repo_root() / "vendor" / "weaponizing-censors" / "zmap_multiple_probes",
        )

    def test_preflight_uses_single_or_multi_zmap_root_by_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            single_root = tmp_path / "single"
            multi_root = tmp_path / "multi"
            single_root.mkdir()
            multi_root.mkdir()

            common = {
                "ip_file": self._touch(tmp_path / "ips.txt"),
                "target_host": "example.com",
                "scan_rate": 1,
                "result_limit": 0,
                "length_threshold": 0,
                "geoip_db_path": self._touch(tmp_path / "GeoLite2-City.mmdb"),
                "scan_count": 1,
                "ttl": 64,
                "network_interface": "eth0",
                "output_root": tmp_path / "runs",
                "process_py": self._touch(tmp_path / "process.py"),
                "ip_take_py": self._touch(tmp_path / "ip_take.py"),
                "magnification_test_py": self._touch(tmp_path / "magnification.py"),
                "analyze_amplify_log_py": self._touch(tmp_path / "analyze.py"),
                "zmap_root": single_root,
                "zmap_multiple_probes_root": multi_root,
                "dry_run": False,
                "python_bin": "python3",
            }

            single_report = preflight_check(ScanConfig(pkt_method="PSH", **common))
            multi_report = preflight_check(ScanConfig(pkt_method=sorted(MULTI_PROBE_METHODS)[0], **common))

            self.assertEqual(self._check_path(single_report, "selected_zmap_root"), str(single_root))
            self.assertEqual(self._check_path(multi_report, "selected_zmap_root"), str(multi_root))

    def test_preflight_checks_real_scan_runtime_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zmap_root = tmp_path / "zmap"
            self._touch(zmap_root / "src" / "zmap")
            cfg = ScanConfig(
                ip_file=self._touch(tmp_path / "ips.txt"),
                target_host="example.com",
                pkt_method="PSH",
                geoip_db_path=self._touch(tmp_path / "GeoLite2-City.mmdb"),
                process_py=self._touch(tmp_path / "process.py"),
                ip_take_py=self._touch(tmp_path / "ip_take.py"),
                magnification_test_py=self._touch(tmp_path / "magnification.py"),
                analyze_amplify_log_py=self._touch(tmp_path / "analyze.py"),
                zmap_root=zmap_root,
                zmap_multiple_probes_root=tmp_path / "unused",
                dry_run=False,
            )

            report = preflight_check(cfg)
            keys = {item["key"] for item in report["checks"]}

            self.assertIn("python_module_geoip2", keys)
            self.assertIn("python_module_scapy", keys)
            self.assertIn("python_module_numpy", keys)
            self.assertIn("command_traceroute", keys)

    def test_preflight_marks_existing_zmap_binary_executable(self):
        if os.name == "nt":
            self.skipTest("Windows does not expose POSIX execute bits consistently")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zmap_root = tmp_path / "zmap"
            zmap_bin = self._touch(zmap_root / "src" / "zmap")
            zmap_bin.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            cfg = ScanConfig(
                ip_file=self._touch(tmp_path / "ips.txt"),
                target_host="example.com",
                pkt_method="PSH",
                geoip_db_path=self._touch(tmp_path / "GeoLite2-City.mmdb"),
                process_py=self._touch(tmp_path / "process.py"),
                ip_take_py=self._touch(tmp_path / "ip_take.py"),
                magnification_test_py=self._touch(tmp_path / "magnification.py"),
                analyze_amplify_log_py=self._touch(tmp_path / "analyze.py"),
                zmap_root=zmap_root,
                zmap_multiple_probes_root=tmp_path / "unused",
                dry_run=False,
            )

            report = preflight_check(cfg)

            self.assertTrue(self._check_ok(report, "zmap_binary"))
            self.assertTrue(os.access(zmap_bin, os.X_OK))

    def test_process_csv_sorts_flags_without_sql_group_concat_subquery(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            input_csv = tmp_path / "raw.csv"
            output_csv = tmp_path / "processed.csv"
            input_csv.write_text(
                "saddr,len,payloadlen,flags\n"
                "192.0.2.1,100,60,PA\n"
                "192.0.2.1,150,80,RA\n",
                encoding="utf-8",
            )

            process_csv_optimized(str(input_csv), str(output_csv), limit_count=0, length_threshold=0)

            with output_csv.open("r", newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["saddr"], "192.0.2.1")
            self.assertEqual(rows[0]["len"], "250")
            self.assertEqual(rows[0]["payloadlen"], "140")
            self.assertEqual(rows[0]["flags"], "PA,RA")
            self.assertEqual(rows[0]["count"], "2")

    def _touch(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        return path

    def _check_path(self, report, key: str) -> str:
        return next(item["path"] for item in report["checks"] if item["key"] == key)

    def _check_ok(self, report, key: str) -> bool:
        return next(item["ok"] for item in report["checks"] if item["key"] == key)


if __name__ == "__main__":
    unittest.main()
