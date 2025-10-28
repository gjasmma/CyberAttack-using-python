# test_secure_app.py
import json
import threading
import time
import unittest
import http.client

import secure_app  # assumes files are in same directory

HOST = "127.0.0.1"
PORT = 8090

def start_server():
    t = threading.Thread(target=secure_app.run, args=(HOST, PORT), daemon=True)
    t.start()
    time.sleep(0.3)  # give server time to start
    return t

def request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    hdrs = {"X-API-Key": secure_app.API_KEY}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
        hdrs["Content-Length"] = str(len(data))
    conn.request(method, path, body=data if body is not None else None, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw) if raw else {}
    except Exception:
        parsed = {}
    return resp.status, parsed

class TestSecureApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_server()

    def test_health_ready(self):
        status, body = request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")

        status, body = request("GET", "/ready")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ready")

    def test_auth_required(self):
        conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
        conn.request("GET", "/health")  # no API key
        resp = conn.getresponse()
        self.assertEqual(resp.status, 401)
        conn.close()

    def test_security_check(self):
        status, body = request("POST", "/security/check", {"level": 5})
        self.assertEqual(status, 200)
        self.assertIn("High", body.get("description", ""))

        status, _ = request("POST", "/security/check", {"level": 6})
        self.assertEqual(status, 400)

    def test_firewall_block_and_enforce(self):
        status, _ = request("POST", "/firewall/block", {"cidr": "127.0.0.1/32"})
        self.assertEqual(status, 200)

        status, _ = request("GET", "/health")
        self.assertEqual(status, 403)

    def test_rate_limit(self):
        secure_app.firewall_blocklist.clear()
        last_status = None
        for _ in range(secure_app.RATE_LIMIT_MAX + 2):
            status, _ = request("GET", "/health")
            last_status = status
        self.assertEqual(last_status, 429)

    def test_tasks_execute_signature(self):
        payload = {"a": 1, "b": 2}
        ts = str(int(time.time()))
        sig = secure_app.sign_payload(payload, ts)
        status, body = request(
            "POST",
            "/tasks/execute",
            {"name": "job", "data": payload, "timestamp": ts, "signature": sig},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")

        status, _ = request(
            "POST",
            "/tasks/execute",
            {"name": "job", "data": payload, "timestamp": ts, "signature": "bad"},
        )
        self.assertEqual(status, 401)

    def test_body_size_limit(self):
        big = "x" * (secure_app.BODY_SIZE_LIMIT + 1)
        status, _ = request("POST", "/security/check", {"level": 3, "pad": big})
        self.assertEqual(status, 413)

    def test_unsupported_media(self):
        conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
        conn.request("POST", "/security/check", body=b'{"level":3}', headers={"X-API-Key": secure_app.API_KEY})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 415)
        conn.close()

    def test_shutdown(self):
        status, body = request("POST", "/shutdown", {})
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "shutting down")
        # Give time for shutdown to complete
        time.sleep(0.2)
        # After shutdown, server should refuse connections
        conn = http.client.HTTPConnection(HOST, PORT, timeout=2)
        with self.assertRaises(Exception):
            conn.request("GET", "/health")

if __name__ == "__main__":
    unittest.main()
