from pathlib import Path
import json
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.modules.setdefault("psutil", mock.Mock())
sys.modules.setdefault("flask_session", mock.Mock(Session=lambda app: None))


def _register_stub(module_name: str, symbol_name: str):
    module = types.ModuleType(module_name)
    setattr(module, symbol_name, type(symbol_name, (), {}))
    sys.modules.setdefault(module_name, module)


_register_stub("attack_resources.memcached.code.tester", "MemcachedTester")
_register_stub("attack_resources.dns.code.tester", "DNSTester")
_register_stub("attack_resources.ntp.code.tester", "NTPTester")
_register_stub("multi_protocol_test", "MultiProtocolTester")

import app as pressure_app


class DnsScanRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.client = pressure_app.app.test_client()
        pressure_app.app.testing = True

        run_dir = self.root / "dns_20260630_122816"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "pipeline.log").write_text("[12:28:16] done\n", encoding="utf-8")
        (run_dir / "qualified_ips.txt").write_text("1.1.1.1\n8.8.8.8\n", encoding="utf-8")
        (run_dir / "scan_summary.json").write_text(
            json.dumps({"qualified_count": 2, "timestamp": "2026-06-30T12:28:16"}),
            encoding="utf-8",
        )
        (run_dir / "final_stats.json").write_text(
            json.dumps(
                {
                    "status": "completed",
                    "stage": "done",
                    "current_stage": None,
                    "tested": 8,
                    "total_tasks": 8,
                    "qualified": 2,
                    "stages": {
                        "loading": {"status": "completed"},
                        "scanning": {"status": "completed"},
                        "filtering": {"status": "completed"},
                        "saving": {"status": "completed"},
                    },
                    "config": {
                        "ip_file": "DNS_test.txt",
                        "query_type": "RRSIG",
                        "use_dnssec": True,
                        "concurrency": 80,
                        "min_amplification": 3.0,
                        "min_reliability": 50.0,
                    },
                }
            ),
            encoding="utf-8",
        )

        self.patches = [
            mock.patch("attack_resources.dns.code.routes.DNS_OUTPUT_ROOT", self.root),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmpdir.cleanup()

    def test_historical_dns_run_detail_returns_persisted_stage_and_config(self):
        response = self.client.get("/api/dns-scan/runs/dns_20260630_122816")
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertFalse(data["is_running"])
        self.assertEqual(data["stats"]["stage"], "done")
        self.assertEqual(data["stats"]["stages"]["saving"]["status"], "completed")
        self.assertEqual(data["config"]["query_type"], "RRSIG")
        self.assertEqual(data["config"]["concurrency"], 80)

    def test_historical_dns_run_list_returns_status(self):
        response = self.client.get("/api/dns-scan/runs")
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertEqual(data["runs"][0]["status"], "completed")
        self.assertEqual(data["runs"][0]["qualified_count"], 2)


if __name__ == "__main__":
    unittest.main()
