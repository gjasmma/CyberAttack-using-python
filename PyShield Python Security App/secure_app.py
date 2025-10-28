# secure_app.py
import json
import time
import hmac
import hashlib
import ipaddress
import logging
import os
import uuid
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler

# -----------------------------
# Configuration (env-overridable)
# -----------------------------
API_KEY = os.getenv("APP_API_KEY", "supersecret")            # replace in production
RATE_LIMIT_WINDOW = int(os.getenv("APP_RATE_WINDOW", "60"))  # seconds
RATE_LIMIT_MAX = int(os.getenv("APP_RATE_MAX", "10"))        # requests per window
SECRET_KEY = os.getenv("APP_SECRET_KEY", "signing-key").encode("utf-8")
BODY_SIZE_LIMIT = int(os.getenv("APP_BODY_LIMIT", "10240"))  # 10KB
ENABLE_ALLOWLIST = os.getenv("APP_ENABLE_ALLOWLIST", "0") == "1"
IP_ALLOWLIST = set(ip.strip() for ip in os.getenv("APP_IP_ALLOWLIST", "").split(",") if ip.strip())

# -----------------------------
# Logging (console + rotating file)
# -----------------------------
log = logging.getLogger("secure-app")
log.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
log.addHandler(console_handler)

file_handler = RotatingFileHandler("secure_app.log", maxBytes=1_000_000, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
log.addHandler(file_handler)

# -----------------------------
# State
# -----------------------------
rate_limits = {}             # ip -> {count, reset}
firewall_blocklist = set()   # CIDR strings
httpd: HTTPServer | None = None  # global reference for shutdown

# -----------------------------
# Security helpers
# -----------------------------
def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    bucket = rate_limits.get(ip)
    if not bucket or now - bucket["reset"] > RATE_LIMIT_WINDOW:
        rate_limits[ip] = {"count": 1, "reset": now}
        return False
    if bucket["count"] < RATE_LIMIT_MAX:
        bucket["count"] += 1
        return False
    return True

def is_blocked(ip: str) -> bool:
    # Allowlist takes precedence if enabled
    if ENABLE_ALLOWLIST and IP_ALLOWLIST:
        if ip not in IP_ALLOWLIST:
            return True

    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # fail closed

    for cidr in firewall_blocklist:
        if ip_addr in ipaddress.ip_network(cidr, strict=False):
            return True
    return False

def sign_payload(data: dict, timestamp: str) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    msg = timestamp.encode() + b"." + canonical
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()

def verify_signature(data: dict, timestamp: str, signature: str, max_skew: int = 300) -> bool:
    try:
        ts = int(timestamp)
    except Exception:
        return False
    now = int(time.time())
    if abs(now - ts) > max_skew:
        return False
    expected = sign_payload(data, timestamp)
    return hmac.compare_digest(expected, signature)

def shutdown_server():
    global httpd
    if httpd:
        log.info("Shutdown requested via API")
        # Use a thread to avoid blocking handler
        threading.Thread(target=httpd.shutdown, daemon=True).start()

# -----------------------------
# HTTP handler
# -----------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "SecureApp/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Silence default server logs; we log explicitly
        pass

    def _security_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _json_response(self, code: int, payload: dict, request_id: str):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self._security_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Request-ID", request_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> bool:
        key = self.headers.get("X-API-Key", "")
        return safe_compare(key, API_KEY)

    def _read_json(self, request_id: str):
        if self.headers.get("Content-Type", "").lower() != "application/json":
            self._json_response(415, {"error": "Unsupported Media Type"}, request_id)
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            self._json_response(411, {"error": "Length Required"}, request_id)
            return None
        if length <= 0 or length > BODY_SIZE_LIMIT:
            self._json_response(413, {"error": "Payload Too Large"}, request_id)
            return None
        try:
            raw = self.rfile.read(length)
            return json.loads(raw)
        except Exception:
            self._json_response(400, {"error": "Invalid JSON"}, request_id)
            return None

    def _prechecks(self, method: str, request_id: str) -> bool:
        client_ip = self.client_address[0]
        log.info(f"req_id={request_id} ip={client_ip} method={method} path={self.path}")
        if not self._auth():
            self._json_response(401, {"error": "Unauthorized"}, request_id)
            return False
        if is_blocked(client_ip):
            self._json_response(403, {"error": "Forbidden"}, request_id)
            return False
        if is_rate_limited(client_ip):
            self._json_response(429, {"error": "Too Many Requests"}, request_id)
            return False
        return True

    def do_PUT(self):
        request_id = str(uuid.uuid4())
        self._json_response(405, {"error": "Method Not Allowed"}, request_id)

    def do_DELETE(self):
        request_id = str(uuid.uuid4())
        self._json_response(405, {"error": "Method Not Allowed"}, request_id)

    def do_GET(self):
        request_id = str(uuid.uuid4())
        if not self._prechecks("GET", request_id):
            return

        if self.path == "/health":
            return self._json_response(200, {"status": "ok"}, request_id)
        elif self.path == "/ready":
            return self._json_response(200, {"status": "ready"}, request_id)
        else:
            return self._json_response(404, {"error": "Not Found"}, request_id)

    def do_POST(self):
        request_id = str(uuid.uuid4())
        if not self._prechecks("POST", request_id):
            return

        body = self._read_json(request_id)
        if body is None:
            return

        if self.path == "/shutdown":
            shutdown_server()
            return self._json_response(200, {"status": "shutting down"}, request_id)

        if self.path == "/security/check":
            try:
                level = int(body.get("level", 5))
            except Exception:
                return self._json_response(400, {"error": "Invalid level"}, request_id)
            if level < 1 or level > 5:
                return self._json_response(400, {"error": "Level out of range"}, request_id)
            desc = "High" if level >= 5 else "Medium" if level >= 3 else "Low"
            return self._json_response(200, {"description": f"Server security is {desc}."}, request_id)

        elif self.path == "/firewall/block":
            cidr = body.get("cidr")
            try:
                ipaddress.ip_network(cidr, strict=False)
                firewall_blocklist.add(cidr)
                log.info(f"firewall add cidr={cidr}")
                return self._json_response(200, {"status": "added", "cidr": cidr}, request_id)
            except Exception:
                return self._json_response(400, {"error": "Invalid CIDR"}, request_id)

        elif self.path == "/tasks/execute":
            name = body.get("name")
            data = body.get("data")
            ts = body.get("timestamp")
            sig = body.get("signature")
            if not isinstance(name, str) or not name or len(name) > 100:
                return self._json_response(400, {"error": "Invalid name"}, request_id)
            if not isinstance(data, dict):
                return self._json_response(400, {"error": "Invalid data"}, request_id)
            if not isinstance(ts, str) or not isinstance(sig, str):
                return self._json_response(400, {"error": "Missing signature or timestamp"}, request_id)
            if not verify_signature(data, ts, sig):
                return self._json_response(401, {"error": "Invalid signature"}, request_id)

            log.info(f"task executed name={name} req_id={request_id}")
            return self._json_response(200, {"status": "ok", "task": name}, request_id)

        else:
            return self._json_response(404, {"error": "Not Found"}, request_id)

# -----------------------------
# Server lifecycle
# -----------------------------
def run(host="0.0.0.0", port=8080):
    global httpd
    httpd = HTTPServer((host, port), Handler)
    log.info(f"Serving on {host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        log.info("Server stopped")

if __name__ == "__main__":
    run()
