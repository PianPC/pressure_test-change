from pathlib import Path
import csv
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


class AttackResourceMemcachedApiTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.client = pressure_app.app.test_client()
        pressure_app.app.testing = True

        resources_dir = self.root / "resources"
        resources_dir.mkdir(parents=True, exist_ok=True)
        (resources_dir / "servers.txt").write_text("203.0.113.10\n203.0.113.11\n", encoding="utf-8")

        run_dir = self.root / "memcached_20260710_120000"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "pipeline.log").write_text("[12:00:00] scan done\n", encoding="utf-8")
        (run_dir / "qualified_ips.txt").write_text("# qualified\n203.0.113.10\n", encoding="utf-8")
        with (run_dir / "scan_results.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["IP", "Amplification"])
            writer.writerow(["203.0.113.10", "42.5"])
        (run_dir / "scan_summary.json").write_text(
            json.dumps({"qualified_count": 1, "timestamp": "2026-07-10T12:00:00"}),
            encoding="utf-8",
        )
        (run_dir / "final_stats.json").write_text(
            json.dumps(
                {
                    "status": "completed",
                    "stage": "done",
                    "current_stage": None,
                    "tested": 4,
                    "total_ips": 4,
                    "qualified": 1,
                    "stages": {
                        "loading": {"status": "completed"},
                        "scanning": {"status": "completed"},
                        "filtering": {"status": "completed"},
                        "saving": {"status": "completed"},
                    },
                    "config": {
                        "ip_file": "servers.txt",
                        "cmd_type": "get",
                        "data_size_kb": 300,
                        "concurrency": 50,
                        "min_amplification": 10.0,
                        "min_reliability": 50.0,
                        "memcached_port": 11211,
                    },
                }
            ),
            encoding="utf-8",
        )

        self.patches = [
            mock.patch("attack_resources.memcached.code.routes.MEMCACHED_OUTPUT_ROOT", self.root),
            mock.patch("attack_resources.memcached.code.routes.MEMCACHED_RESOURCES_ROOT", resources_dir),
            mock.patch("attack_resources.shared.attack_resource_api.MEMCACHED_OUTPUT_ROOT", self.root),
            mock.patch("attack_resources.shared.attack_resource_api.memcached_registry.active_run_ids", return_value=[]),
            mock.patch("attack_resources.shared.attack_resource_api.memcached_registry.is_running", return_value=False),
            mock.patch("attack_resources.shared.attack_resource_api.memcached_registry.get_scanner", return_value=None),
            mock.patch("attack_resources.shared.attack_resource_api.memcached_registry.get_error", return_value=""),
            mock.patch("attack_resources.shared.attack_resource_api.memcached_registry.get_config", return_value=None),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmpdir.cleanup()

    def test_memcached_resources_are_available_through_unified_api(self):
        response = self.client.get("/api/attack-resource/memcached/resources")
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertEqual([item["name"] for item in data["resources"]], ["servers.txt"])

    def test_memcached_run_detail_returns_unified_payload_with_extensions(self):
        response = self.client.get("/api/attack-resource/memcached/runs/memcached_20260710_120000")
        data = response.get_json()

        self.assertTrue(data["success"])
        run = data["run"]
        self.assertEqual(run["proto"], "memcached")
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["summary_stats"]["qualified_count"], 1)
        self.assertEqual(run["config"]["cmd_type"], "get")
        self.assertEqual(run["stages"][-1]["status"], "completed")
        self.assertEqual(run["result_preview"]["items"], ["203.0.113.10"])
        self.assertEqual(run["artifacts"][0]["name"], "final_stats.json")

    def test_memcached_results_and_file_read_use_unified_api(self):
        results_response = self.client.get("/api/attack-resource/memcached/runs/memcached_20260710_120000/results")
        file_response = self.client.get("/api/attack-resource/memcached/runs/memcached_20260710_120000/files/qualified_ips.txt")

        results_data = results_response.get_json()
        file_data = file_response.get_json()

        self.assertTrue(results_data["success"])
        self.assertEqual(results_data["qualified_ips"], ["203.0.113.10"])
        self.assertEqual(results_data["qualified_count"], 1)
        self.assertEqual(results_data["results"][0]["IP"], "203.0.113.10")

        self.assertTrue(file_data["success"])
        self.assertEqual(file_data["file"]["name"], "qualified_ips.txt")
        self.assertIn("203.0.113.10", file_data["file"]["content"])


if __name__ == "__main__":
    unittest.main()
