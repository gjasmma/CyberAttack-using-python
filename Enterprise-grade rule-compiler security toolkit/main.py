#!/usr/bin/env python3
# Enterprise Rule-Compiler Security Toolkit (defensive-only)
# Python 3.10+
# Safe by design: detection, analysis, reporting. No offensive capabilities.

import argparse
import re
import json
import hashlib
import os
import sys
import time
import math
import csv
import shutil
import socket
import ssl
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Optional modules with graceful fallback
try:
    import psutil
except Exception:
    psutil = None

try:
    import requests
except Exception:
    requests = None

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
CONFIG = {
    "profile": "enterprise",  # lab or enterprise
    "db_dir": str(Path.home() / "SecCompilerDB"),
    "report_dir": str(Path.home() / "SecCompilerReports"),
    "quarantine_dir": str(Path.home() / "SecCompilerQuarantine"),
    "honeypot_dir": str(Path.home() / "SecCompilerHoneypot"),
    "entropy_threshold": 7.5,
    "max_scan_size_mb": 200,
    "report_formats": ["json", "csv"],
    "process_red_flags": ["powershell", "mshta", "wscript", "cscript", "tor", "nc", "netcat"],
    "default_rule_set": "rules.txt",
    "loop_interval_sec": 60,  # default loop interval
    # Integrations (stubs with safe failures)
    "syslog_udp_host": None,  # e.g., "127.0.0.1"
    "syslog_udp_port": 514,
    "splunk_hec_url": None,  # e.g., "https://splunk.example.com:8088/services/collector"
    "splunk_hec_token": None,
    "elastic_endpoint": None,  # e.g., "http://elastic.example.com:9200/index/_doc"
}

for d in ["db_dir", "report_dir", "quarantine_dir", "honeypot_dir"]:
    Path(CONFIG[d]).mkdir(parents=True, exist_ok=True)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def file_size_mb(p: Path) -> float:
    try:
        return p.stat().st_size / (1024 * 1024)
    except Exception:
        return 0.0

def read_bytes(p: Path, cap: int = 1024 * 1024) -> bytes:
    if not p.is_file():
        return b""
    with p.open("rb") as f:
        return f.read(cap)

def to_text(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0]*256
    for x in b:
        counts[x] += 1
    ent = 0.0
    n = len(b)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def hash_all(p: Path) -> Dict[str, str]:
    res = {"md5": "", "sha1": "", "sha256": ""}
    if not p.is_file():
        return res
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    res["md5"] = md5.hexdigest()
    res["sha1"] = sha1.hexdigest()
    res["sha256"] = sha256.hexdigest()
    return res

def write_reports(name: str, items: List[Dict[str, Any]]) -> List[Path]:
    outputs = []
    base = Path(CONFIG["report_dir"]) / f"{name}_{int(time.time())}"
    # JSON
    if "json" in CONFIG["report_formats"]:
        pj = Path(str(base) + ".json")
        with pj.open("w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
        outputs.append(pj)
    # CSV
    if "csv" in CONFIG["report_formats"]:
        pc = Path(str(base) + ".csv")
        if items:
            keys = sorted({k for it in items for k in it.keys()})
            with pc.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                w.writerows(items)
        outputs.append(pc)
    return outputs

def quarantine_copy(src: Path) -> Optional[Path]:
    try:
        dest = Path(CONFIG["quarantine_dir"]) / f"{src.name}.{int(time.time())}.quarantined"
        shutil.copy2(src, dest)
        return dest
    except Exception:
        return None

def emit_syslog(event: Dict[str, Any]):
    host = CONFIG["syslog_udp_host"]
    port = CONFIG["syslog_udp_port"]
    if not host:
        return
    try:
        msg = f"<134> {ts()} SEC_COMPILER {json.dumps(event, ensure_ascii=False)}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode("utf-8"), (host, port))
        sock.close()
    except Exception:
        pass

def emit_splunk(event: Dict[str, Any]):
    url = CONFIG["splunk_hec_url"]
    token = CONFIG["splunk_hec_token"]
    if not (url and token and requests):
        return
    try:
        headers = {"Authorization": f"Splunk {token}"}
        payload = {"time": int(time.time()), "event": event, "sourcetype": "sec_compiler"}
        requests.post(url, headers=headers, json=payload, timeout=5)
    except Exception:
        pass

def emit_elastic(event: Dict[str, Any]):
    endpoint = CONFIG["elastic_endpoint"]
    if not (endpoint and requests):
        return
    try:
        requests.post(endpoint, json=event, timeout=5)
    except Exception:
        pass

def emit_all(event: Dict[str, Any]):
    emit_syslog(event)
    emit_splunk(event)
    emit_elastic(event)

# -----------------------------------------------------------------------------
# Rule DSL & compiler
# -----------------------------------------------------------------------------
"""
Rule DSL (line-based; comments start with #)
Types:
  HASH sha256=<hex> tag=<name>
  STR pattern=<regex> scope=(bytes|text) tag=<name>
  DOMAIN blacklist=<domain> tag=<name>
  IP blacklist=<ipv4> tag=<name>

Examples:
  HASH sha256=aaaaaaaa... tag=known_bad
  STR pattern=eval\\s*\\( scope=text tag=obf_js
  DOMAIN blacklist=bad.example tag=block_domain
  IP blacklist=203.0.113.23 tag=block_ip
"""

RULES_SCHEMA = ("HASH", "STR", "DOMAIN", "IP")

class CompiledRules:
    def __init__(self):
        self.hashes_sha256: Dict[str, str] = {}
        self.str_text: List[Tuple[re.Pattern, str]] = []
        self.str_bytes: List[Tuple[re.Pattern, str]] = []
        self.domains: Dict[str, str] = {}
        self.ips: Dict[str, str] = {}
        self.meta: Dict[str, Any] = {"compiled_at": ts(), "source_files": []}

def parse_rule_line(line: str) -> Optional[Dict[str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    if parts[0] not in RULES_SCHEMA:
        raise ValueError(f"Unknown rule type: {parts[0]}")
    entry = {"type": parts[0]}
    for token in parts[1:]:
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        entry[k.lower()] = v
    return entry

def compile_rules(files: List[Path]) -> CompiledRules:
    cr = CompiledRules()
    for fp in files:
        if not fp.exists():
            continue
        cr.meta["source_files"].append(str(fp))
        with fp.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                try:
                    e = parse_rule_line(line)
                    if not e:
                        continue
                    if e["type"] == "HASH" and "sha256" in e and "tag" in e:
                        cr.hashes_sha256[e["sha256"].lower()] = e["tag"]
                    elif e["type"] == "STR" and "pattern" in e and "tag" in e:
                        flags = re.IGNORECASE | re.DOTALL
                        pat = re.compile(e["pattern"], flags)
                        scope = e.get("scope", "text").lower()
                        if scope == "bytes":
                            cr.str_bytes.append((pat, e["tag"]))
                        else:
                            cr.str_text.append((pat, e["tag"]))
                    elif e["type"] == "DOMAIN" and "blacklist" in e and "tag" in e:
                        cr.domains[e["blacklist"].lower()] = e["tag"]
                    elif e["type"] == "IP" and "blacklist" in e and "tag" in e:
                        cr.ips[e["blacklist"]] = e["tag"]
                except Exception:
                    # Skip invalid line; keep compiling
                    pass
    return cr

def rules_db_path() -> Path:
    return Path(CONFIG["db_dir"]) / "compiled_rules.json"

def save_compiled_rules(cr: CompiledRules) -> Path:
    data = {
        "hashes_sha256": cr.hashes_sha256,
        "str_text": [[p.pattern, t] for p, t in cr.str_text],
        "str_bytes": [[p.pattern, t] for p, t in cr.str_bytes],
        "domains": cr.domains,
        "ips": cr.ips,
        "meta": cr.meta,
        "db_hash": "",
    }
    dump = json.dumps(data, sort_keys=True).encode("utf-8")
    db_hash = hashlib.sha256(dump).hexdigest()
    data["db_hash"] = db_hash
    p = rules_db_path()
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return p

def load_compiled_rules() -> CompiledRules:
    p = rules_db_path()
    cr = CompiledRules()
    if not p.exists():
        return cr
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    temp = dict(data)
    db_hash = temp.pop("db_hash", "")
    calc = hashlib.sha256(json.dumps(temp, sort_keys=True).encode("utf-8")).hexdigest()
    if db_hash and db_hash != calc:
        raise ValueError("Signature DB integrity check failed.")
    cr.hashes_sha256 = {k.lower(): v for k, v in data.get("hashes_sha256", {}).items()}
    cr.str_text = [(re.compile(pat, re.IGNORECASE | re.DOTALL), tag) for pat, tag in data.get("str_text", [])]
    cr.str_bytes = [(re.compile(pat, re.IGNORECASE | re.DOTALL), tag) for pat, tag in data.get("str_bytes", [])]
    cr.domains = {k.lower(): v for k, v in data.get("domains", {}).items()}
    cr.ips = data.get("ips", {})
    cr.meta = data.get("meta", {})
    return cr

# -----------------------------------------------------------------------------
# Detectors
# -----------------------------------------------------------------------------
def scan_file(p: Path, cr: CompiledRules) -> List[Dict[str, Any]]:
    findings = []
    if not p.exists() or p.is_dir():
        return findings
    if file_size_mb(p) > CONFIG["max_scan_size_mb"]:
        return findings

    b = read_bytes(p)
    txt = to_text(b)
    hashes = hash_all(p)
    entropy = round(shannon_entropy(b), 3)

    # Hash hit
    tag = cr.hashes_sha256.get(hashes["sha256"].lower())
    if tag:
        event = {"type": "hash_hit", "tag": tag, "path": str(p), "sha256": hashes["sha256"], "time": ts()}
        findings.append(event)
        emit_all(event)

    # String rules (text)
    for pat, t in cr.str_text:
        if pat.search(txt):
            event = {"type": "string_match_text", "tag": t, "pattern": pat.pattern, "path": str(p), "time": ts()}
            findings.append(event)
            emit_all(event)

    # String rules (bytes)
    # Decode bytes as latin1 for regex search; safe, no execution
    txt_bytes = b.decode("latin1", errors="ignore")
    for pat, t in cr.str_bytes:
        if pat.search(txt_bytes):
            event = {"type": "string_match_bytes", "tag": t, "pattern": pat.pattern, "path": str(p), "time": ts()}
            findings.append(event)
            emit_all(event)

    # Entropy heuristic
    if entropy >= CONFIG["entropy_threshold"]:
        event = {"type": "entropy_high", "value": entropy, "path": str(p), "time": ts()}
        findings.append(event)
        emit_all(event)

    # Quarantine policy
    strong = any(f["type"] in ("hash_hit", "string_match_text", "string_match_bytes") for f in findings)
    if strong and entropy >= CONFIG["entropy_threshold"]:
        qp = quarantine_copy(p)
        event = {"type": "quarantine", "source": str(p), "dest": str(qp) if qp else None, "time": ts()}
        findings.append(event)
        emit_all(event)

    # Summary
    summary = {
        "type": "scan_summary",
        "path": str(p),
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "entropy": entropy,
        "matches": [f.get("tag") for f in findings if "tag" in f],
        "time": ts()
    }
    findings.append(summary)
    return findings

def scan_dir(root: Path, cr: CompiledRules) -> List[Dict[str, Any]]:
    allf = []
    for p in root.rglob("*"):
        if p.is_file():
            allf.extend(scan_file(p, cr))
    return allf

def check_ssl(host: str, port: int = 443) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    result = {"host": host, "port": port, "ssl_ok": False, "subject": None, "issuer": None, "expires": None}
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["ssl_ok"] = True
                result["subject"] = cert.get("subject")
                result["issuer"] = cert.get("issuer")
                result["expires"] = cert.get("notAfter")
    except Exception:
        pass
    return result

def url_indicators(url: str, cr: CompiledRules) -> List[Dict[str, Any]]:
    results = []
    domain = re.sub(r"^https?://", "", url).split("/")[0].lower()
    # Domain blacklist
    tag = cr.domains.get(domain)
    if tag:
        event = {"type": "domain_blacklist", "domain": domain, "tag": tag, "time": ts()}
        results.append(event)
        emit_all(event)
    # Indicators
    looks_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
    if looks_ip:
        results.append({"type": "indicator", "domain": domain, "label": "looks_ip", "time": ts()})
    if domain.endswith(".xyz") or domain.endswith(".top"):
        results.append({"type": "indicator", "domain": domain, "label": "suspicious_tld", "time": ts()})
    # SSL check
    sslres = check_ssl(domain)
    results.append({"type": "ssl_check", **sslres, "time": ts()})
    # Summary
    results.append({"type": "url_summary", "url": url, "domain": domain, "time": ts()})
    return results

def ip_reputation(ip: str, cr: CompiledRules) -> List[Dict[str, Any]]:
    res = []
    tag = cr.ips.get(ip)
    event = {"type": "ip_reputation", "ip": ip, "blacklisted": bool(tag), "tag": tag, "time": ts()}
    res.append(event)
    emit_all(event)
    return res

def list_process_red_flags() -> List[Dict[str, Any]]:
    out = []
    if not psutil:
        return out
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        name = (proc.info.get("name") or "").lower()
        cmdline = " ".join(proc.info.get("cmdline") or []).lower()
        for flag in CONFIG["process_red_flags"]:
            if flag in name or flag in cmdline:
                event = {
                    "type": "process_flag",
                    "pid": proc.info.get("pid"),
                    "name": proc.info.get("name"),
                    "cmdline": proc.info.get("cmdline"),
                    "flag": flag,
                    "time": ts()
                }
                out.append(event)
                emit_all(event)
                break
    return out

# -----------------------------------------------------------------------------
# Ransomware heuristics (honeypot + mass rename ratio)
# -----------------------------------------------------------------------------
def init_honeypot():
    hp = Path(CONFIG["honeypot_dir"])
    hp.mkdir(parents=True, exist_ok=True)
    seeds = ["invoice.docx", "photos.zip", "notes.txt", "backup.db"]
    for s in seeds:
        p = hp / s
        if not p.exists():
            with p.open("wb") as f:
                f.write(os.urandom(1024))

def check_honeypot_events() -> List[Dict[str, Any]]:
    hp = Path(CONFIG["honeypot_dir"])
    findings = []
    now = time.time()
    ransomware_ext = {".locked", ".crypt", ".enc", ".crypted"}
    for p in hp.glob("*"):
        try:
            st = p.stat()
            age = now - st.st_mtime
            if age < 60:
                event = {"type": "honeypot_alert", "path": str(p), "reason": "recent_modification", "time": ts()}
                findings.append(event)
                emit_all(event)
            if p.suffix.lower() in ransomware_ext:
                event = {"type": "honeypot_alert", "path": str(p), "reason": "extension_change", "time": ts()}
                findings.append(event)
                emit_all(event)
        except Exception:
            continue
    return findings

def ransomware_scan_dir(target: Path) -> List[Dict[str, Any]]:
    findings = []
    ransomware_ext = {".locked", ".crypt", ".enc", ".crypted"}
    counts = {"total": 0, "changed_ext": 0}
    for p in target.rglob("*"):
        if p.is_file():
            counts["total"] += 1
            if p.suffix.lower() in ransomware_ext:
                counts["changed_ext"] += 1
    ratio = (counts["changed_ext"] / counts["total"]) if counts["total"] else 0.0
    if ratio >= 0.2:
        event = {"type": "ransomware_behavior", "dir": str(target), "changed_ratio": round(ratio, 3), "time": ts()}
        findings.append(event)
        emit_all(event)
    findings.extend(check_honeypot_events())
    return findings

# -----------------------------------------------------------------------------
# CLI commands
# -----------------------------------------------------------------------------
def cmd_compile(args):
    rule_files = [Path(r) for r in (args.rules or [])]
    if not rule_files and Path(CONFIG["default_rule_set"]).exists():
        rule_files = [Path(CONFIG["default_rule_set"])]
    cr = compile_rules(rule_files)
    p = save_compiled_rules(cr)
    print(f"[+] Compiled {len(rule_files)} rule file(s). DB: {p}")

def cmd_scan(args):
    cr = load_compiled_rules()
    target = Path(args.path)
    findings = []
    if target.is_file():
        findings = scan_file(target, cr)
    elif target.is_dir():
        findings = scan_dir(target, cr)
    else:
        print("[-] Target not found.")
        sys.exit(2)
    outs = write_reports("scan", findings)
    print(f"[+] Scan complete. Reports: {[str(o) for o in outs]}")

def cmd_url(args):
    cr = load_compiled_rules()
    results = url_indicators(args.url, cr)
    outs = write_reports("url", results)
    print(f"[+] URL analysis complete. Reports: {[str(o) for o in outs]}")

def cmd_ip(args):
    cr = load_compiled_rules()
    results = ip_reputation(args.ip, cr)
    outs = write_reports("ip", results)
    print(f"[+] IP check complete. Reports: {[str(o) for o in outs]}")

def cmd_process(args):
    results = list_process_red_flags()
    outs = write_reports("process", results)
    print(f"[+] Process observation complete. Reports: {[str(o) for o in outs]}")

def cmd_quarantine(args):
    src = Path(args.path)
    dest = quarantine_copy(src)
    results = [{"type": "manual_quarantine", "source": str(src), "dest": str(dest) if dest else None, "time": ts()}]
    outs = write_reports("quarantine", results)
    print(f"[+] Quarantine complete. Reports: {[str(o) for o in outs]}")

def cmd_ransomware(args):
    init_honeypot()
    target = Path(args.dir) if args.dir else Path.home()
    results = ransomware_scan_dir(target)
    outs = write_reports("ransomware", results)
    print(f"[+] Ransomware heuristic complete. Reports: {[str(o) for o in outs]}")

def cmd_loop(args):
    # Loop across selected modules
    modules = [m.strip().lower() for m in (args.modules or ["process", "ransomware"])]
    interval = args.interval or CONFIG["loop_interval_sec"]
    target_path = Path(args.path) if args.path else None
    url = args.url
    ip = args.ip
    print(f"[+] Loop started. Modules={modules}, interval={interval}s. Ctrl+C to stop.")
    init_honeypot()
    while True:
        try:
            cr = load_compiled_rules()
            if "scan" in modules and target_path:
                findings = []
                if target_path.is_file():
                    findings = scan_file(target_path, cr)
                elif target_path.is_dir():
                    findings = scan_dir(target_path, cr)
                outs = write_reports("scan_loop", findings)
                print(f"  [scan] Reports: {[str(o) for o in outs]}")
            if "url" in modules and url:
                outs = write_reports("url_loop", url_indicators(url, cr))
                print(f"  [url] Reports: {[str(o) for o in outs]}")
            if "ip" in modules and ip:
                outs = write_reports("ip_loop", ip_reputation(ip, cr))
                print(f"  [ip] Reports: {[str(o) for o in outs]}")
            if "process" in modules:
                outs = write_reports("process_loop", list_process_red_flags())
                print(f"  [process] Reports: {[str(o) for o in outs]}")
            if "ransomware" in modules:
                outs = write_reports("ransomware_loop", ransomware_scan_dir(Path.home()))
                print(f"  [ransomware] Reports: {[str(o) for o in outs]}")
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[+] Loop stopped by user.")
            break
        except Exception as ex:
            # Keep loop alive; log an event
            event = {"type": "loop_error", "error": str(ex), "time": ts()}
            emit_all(event)
            print(f"  [!] Loop error: {ex}")
            time.sleep(interval)

# -----------------------------------------------------------------------------
# Argument parser
# -----------------------------------------------------------------------------
def build_argparser():
    p = argparse.ArgumentParser(description="Enterprise Rule-Compiler Security Toolkit (defensive)")
    sub = p.add_subparsers(dest="cmd")

    p_compile = sub.add_parser("compile", help="Compile rule files into signature DB")
    p_compile.add_argument("--rules", nargs="*", help="Paths to rule files")
    p_compile.set_defaults(func=cmd_compile)

    p_scan = sub.add_parser("scan", help="Scan file or directory using compiled rules")
    p_scan.add_argument("path", help="File or directory")
    p_scan.set_defaults(func=cmd_scan)

    p_url = sub.add_parser("url", help="Analyze a URL/domain")
    p_url.add_argument("url", help="URL to check")
    p_url.set_defaults(func=cmd_url)

    p_ip = sub.add_parser("ip", help="Check IP against reputation rules")
    p_ip.add_argument("ip", help="IPv4 address")
    p_ip.set_defaults(func=cmd_ip)

    p_proc = sub.add_parser("process", help="List processes with red flags")
    p_proc.set_defaults(func=cmd_process)

    p_q = sub.add_parser("quarantine", help="Quarantine a file (copy to quarantine dir)")
    p_q.add_argument("path", help="Path to file")
    p_q.set_defaults(func=cmd_quarantine)

    p_r = sub.add_parser("ransomware", help="Run ransomware behavior heuristics (with honeypot)")
    p_r.add_argument("--dir", help="Directory to evaluate; default=HOME")
    p_r.set_defaults(func=cmd_ransomware)

    p_loop = sub.add_parser("loop", help="Run modules continuously in a loop")
    p_loop.add_argument("--modules", nargs="*", help="Modules to loop: scan url ip process ransomware")
    p_loop.add_argument("--interval", type=int, help=f"Loop interval seconds (default {CONFIG['loop_interval_sec']})")
    p_loop.add_argument("--path", help="Target path for scan module")
    p_loop.add_argument("--url", help="URL for url module")
    p_loop.add_argument("--ip", help="IP for ip module")
    p_loop.set_defaults(func=cmd_loop)

    return p

def main():
    parser = build_argparser()
    args = parser.parse_args()
    if not args.cmd:
        print("Usage examples:")
        print("  python sec_compiler.py compile --rules rules.txt more_rules.txt")
        print("  python sec_compiler.py scan /path/to/dir")
        print("  python sec_compiler.py url https://example.com")
        print("  python sec_compiler.py ip 203.0.113.23")
        print("  python sec_compiler.py process")
        print("  python sec_compiler.py ransomware --dir /path/to/dir")
        print("  python sec_compiler.py loop --modules process ransomware --interval 60")
        sys.exit(0)
    args.func(args)

if __name__ == "__main__":
    main()
