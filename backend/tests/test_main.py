import socket
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app, scan_tcp_ports


class CybersecurityAssistantTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})

    def test_valid_url(self):
        response = self.client.post(
            "/security-check", json={"url": "https://example.com"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["hostname"], "example.com")
        self.assertEqual(response.json()["protocol"], "https")
        self.assertIn("risk_level", response.json())

    def test_invalid_url(self):
        response = self.client.post(
            "/security-check", json={"url": "javascript:alert(1)"}
        )
        self.assertEqual(response.status_code, 400)

    def test_url_with_malformed_hostname(self):
        response = self.client.post(
            "/security-check", json={"url": "https://invalid_host.example"}
        )
        self.assertEqual(response.status_code, 400)

    def test_localhost_port_scan(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            response = self.client.post(
                "/scan",
                json={
                    "host": "127.0.0.1",
                    "ports": str(port),
                    "confirm_authorized": True,
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["open_ports"], [port])
        self.assertEqual(response.json()["scanned_ports"], [port])

    def test_invalid_port(self):
        response = self.client.post(
            "/scan",
            json={"host": "127.0.0.1", "ports": "0", "confirm_authorized": True},
        )
        self.assertEqual(response.status_code, 400)

    def test_empty_host(self):
        response = self.client.post(
            "/scan",
            json={"host": "", "ports": "80", "confirm_authorized": True},
        )
        self.assertEqual(response.status_code, 400)

    def test_excessive_number_of_ports(self):
        ports = ",".join(str(port) for port in range(1, 52))
        response = self.client.post(
            "/scan",
            json={"host": "127.0.0.1", "ports": ports, "confirm_authorized": True},
        )
        self.assertEqual(response.status_code, 400)

    def test_timeout_is_not_reported_as_closed(self):
        with patch("main.socket.create_connection", side_effect=socket.timeout):
            result = scan_tcp_ports("127.0.0.1", [443])

        self.assertEqual(result["closed_ports"], [])
        self.assertEqual(result["errors"][0]["port"], 443)


if __name__ == "__main__":
    unittest.main()
