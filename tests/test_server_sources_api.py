from pathlib import Path
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


def _geo(ip: str, country: str = "United States", country_code: str = "US", region: str = "California", region_code: str = "CA"):
    return {
        "ip": ip,
        "lat": 37.7749,
        "lon": -122.4194,
        "country": country,
        "country_code": country_code,
        "region": region,
        "region_code": region_code,
        "city": "San Francisco",
        "isp": "Test ISP",
        "cached_at": 0,
    }


class ServerSourcesApiTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.client = pressure_app.app.test_client()
        pressure_app.app.testing = True

        self._write("memcached/resources/servers.txt", "203.0.113.10\n")
        self._write("dns/resources/servers.txt", "8.8.8.8\n")
        self._write("ntp/resources/servers.txt", "129.6.15.28\n")
        self._write("tcp/resources/ip_lists/alpha.txt", "8.8.8.8\n1.1.1.1\n")
        self._write("tcp/resources/ip_lists/beta.txt", "8.8.8.8\n9.9.9.9\n")

        geo_lookup = {
            "8.8.8.8": _geo("8.8.8.8"),
            "1.1.1.1": _geo("1.1.1.1"),
            "9.9.9.9": _geo("9.9.9.9"),
            "203.0.113.10": _geo("203.0.113.10"),
            "129.6.15.28": _geo("129.6.15.28"),
        }

        self.patches = [
            mock.patch.object(pressure_app, "ATTACK_RESOURCES_ROOT", str(self.root)),
            mock.patch.object(pressure_app, "load_geoip_cache", return_value={}),
            mock.patch.object(pressure_app, "save_geoip_cache", return_value=None),
            mock.patch.object(
                pressure_app,
                "query_geoip_local_batch",
                side_effect=lambda ips: {ip: geo_lookup[ip] for ip in ips if ip in geo_lookup},
            ),
            mock.patch.object(pressure_app, "query_geoip_batch", return_value={}),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmpdir.cleanup()

    def test_lists_available_sources_for_single_and_multi_file_protocols(self):
        tcp_response = self.client.get("/api/servers/tcp/files")
        memcached_response = self.client.get("/api/servers/memcached/files")

        tcp_data = tcp_response.get_json()
        memcached_data = memcached_response.get_json()

        self.assertTrue(tcp_data["success"])
        self.assertEqual([item["name"] for item in tcp_data["files"]], ["alpha.txt", "beta.txt"])
        self.assertTrue(memcached_data["success"])
        self.assertEqual([item["name"] for item in memcached_data["files"]], ["servers.txt"])

    def test_tcp_geo_aggregates_selected_files(self):
        response = self.client.get("/api/servers/tcp/geo?files=alpha.txt&files=beta.txt")
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["located_count"], 3)
        self.assertEqual(sorted(point["ip"] for point in data["points"]), ["1.1.1.1", "8.8.8.8", "9.9.9.9"])

    def test_tcp_file_reads_and_updates_only_the_selected_source(self):
        get_response = self.client.get("/api/servers/tcp/file?source=alpha.txt")
        get_data = get_response.get_json()

        self.assertTrue(get_data["success"])
        self.assertEqual(get_data["file"]["source"], "alpha.txt")
        self.assertIn("1.1.1.1", get_data["file"]["content"])

        put_response = self.client.put(
            "/api/servers/tcp/file?source=alpha.txt",
            json={"content": "# updated\n4.4.4.4\n"},
        )
        put_data = put_response.get_json()

        self.assertTrue(put_data["success"])
        self.assertEqual((self.root / "tcp/resources/ip_lists/alpha.txt").read_text(encoding="utf-8"), "# updated\n4.4.4.4\n")
        self.assertEqual((self.root / "tcp/resources/ip_lists/beta.txt").read_text(encoding="utf-8"), "8.8.8.8\n9.9.9.9\n")

    def _write(self, relative_path: str, content: str) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
