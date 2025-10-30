// securityAgent.js
"use strict";

const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { exec, execSync } = require("child_process");

// ---------------- CONFIG ----------------
const CONFIG_PATH = path.join(__dirname, "config.json");
let CFG = loadConfig();

function loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
    return JSON.parse(raw);
  } catch (e) {
    console.error("Failed to load config.json. Using defaults.", e.message);
    return {
      allowList: ["127.0.0.1"],
      blockList: [],
      integrityFiles: [],
      processAllowList: ["explorer.exe", "svchost.exe", "cmd.exe", "powershell.exe", "node.exe"],
      processBlockList: [],
      expectedPorts: [80, 443],
      usbWatchIntervalSec: 60,
      integrityIntervalSec: 300,
      processIntervalSec: 60,
      portsIntervalSec: 120,
      healthIntervalSec: 60,
      updatesIntervalSec: 3600,
      logDir: path.join(__dirname, "logs"),
      cpuLoadWarn: 0.9, // 90% of cores
      memFreeWarnMB: 512
    };
  }
}

// ---------------- LOGGING ----------------
ensureDir(CFG.logDir);
const LOG_FILE = path.join(CFG.logDir, `agent-${new Date().toISOString().slice(0,10)}.log`);

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function log(type, message, data = {}) {
  const entry = { ts: new Date().toISOString(), type, message, data };
  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + "\n");
  // Keep console quiet; only surface important notices
  if (type === "ALERT" || type === "ERROR") console.log(`${type}: ${message}`);
}

// ---------------- FIREWALL (SIM) ----------------
function applyFirewallRules(ip) {
  if (CFG.allowList.includes(ip)) {
    log("INFO", `Allowed traffic`, { ip });
  } else if (CFG.blockList.includes(ip)) {
    log("ALERT", `Blocked traffic`, { ip });
  } else {
    log("WARN", `Unknown traffic`, { ip });
  }
}

// ---------------- FILE INTEGRITY ----------------
function hashFile(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function checkFileIntegrityOnce() {
  for (const f of CFG.integrityFiles) {
    const { path: filePath, knownHash } = f;
    if (!fs.existsSync(filePath)) {
      log("ERROR", "Integrity file missing", { filePath });
      continue;
    }
    try {
      const current = hashFile(filePath);
      if (!knownHash) {
        // First-run: record baseline
        f.knownHash = current;
        persistConfig();
        log("INFO", "Baseline hash recorded", { filePath, hash: current });
      } else if (current !== knownHash) {
        log("ALERT", "File modified", { filePath, expected: knownHash, actual: current });
      }
    } catch (e) {
      log("ERROR", "Hashing failed", { filePath, error: e.message });
    }
  }
}

function persistConfig() {
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(CFG, null, 2));
  } catch (e) {
    log("ERROR", "Failed to persist config", { error: e.message });
  }
}

// ---------------- PROCESS MONITOR ----------------
function listProcesses() {
  try {
    const out = execSync(`wmic process get Name,ProcessId /FORMAT:CSV`, { stdio: ["ignore", "pipe", "pipe"] }).toString();
    // CSV with headers Node,Name,ProcessId
    const lines = out.trim().split(/\r?\n/).slice(1); // skip header
    const procs = [];
    for (const line of lines) {
      const parts = line.split(",");
      const name = parts[1]?.trim();
      const pid = Number(parts[2]);
      if (name) procs.push({ name, pid });
    }
    return procs;
  } catch (e) {
    log("ERROR", "Process listing failed", { error: e.message });
    return [];
  }
}

function checkProcesses() {
  const procs = listProcesses();
  const names = new Set(procs.map(p => p.name.toLowerCase()));
  for (const bad of CFG.processBlockList) {
    if (names.has(bad.toLowerCase())) {
      log("ALERT", "Blocked process detected", { process: bad });
    }
  }
  for (const name of names) {
    const allowed = CFG.processAllowList.map(x => x.toLowerCase());
    if (!allowed.includes(name)) {
      log("WARN", "Unknown process running", { process: name });
    }
  }
}

// ---------------- PORT MONITOR ----------------
function listListeningPorts() {
  try {
    const out = execSync(`netstat -ano`, { stdio: ["ignore", "pipe", "pipe"] }).toString();
    const lines = out.split(/\r?\n/).filter(l => l.includes("LISTENING"));
    const ports = new Set();
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const localAddr = parts[1]; // e.g., 0.0.0.0:8080
      const port = Number(localAddr.split(":").pop());
      if (!Number.isNaN(port)) ports.add(port);
    }
    return Array.from(ports);
  } catch (e) {
    log("ERROR", "Port listing failed", { error: e.message });
    return [];
  }
}

function checkPorts() {
  const ports = listListeningPorts();
  for (const p of ports) {
    if (!CFG.expectedPorts.includes(p)) {
      log("ALERT", "Unexpected listening port", { port: p });
    }
  }
}

// ---------------- USB WATCH ----------------
function checkUSBDevices() {
  try {
    const out = execSync(`powershell -NoProfile -Command "Get-PnpDevice -Class DiskDrive | Select-Object FriendlyName,InstanceId"`, { stdio: ["ignore", "pipe", "pipe"] }).toString();
    const devices = out.trim().split(/\r?\n/).filter(Boolean);
    log("INFO", "USB devices snapshot", { count: devices.length });
  } catch (e) {
    log("ERROR", "USB device check failed", { error: e.message });
  }
}

// ---------------- WINDOWS UPDATE CHECK ----------------
function checkWindowsUpdates() {
  try {
    const out = execSync(`powershell -NoProfile -Command "Get-WindowsUpdate -AcceptAll -IgnoreReboot | Select-Object Title,KB,Size"`, { stdio: ["ignore", "pipe", "pipe"] }).toString();
    if (out.trim().length === 0) {
      log("INFO", "No pending Windows updates");
    } else {
      log("WARN", "Pending Windows updates", { details: out });
    }
  } catch (e) {
    // If PS module not installed, capture the error but don't spam
    log("ERROR", "Windows update check failed", { error: e.message });
  }
}

// ---------------- HEALTH ----------------
function checkHealth() {
  const freeMB = os.freemem() / 1024 / 1024;
  const totalMB = os.totalmem() / 1024 / 1024;
  const load = cpuLoadApprox();
  if (load > CFG.cpuLoadWarn) {
    log("ALERT", "High CPU load", { load });
  }
  if (freeMB < CFG.memFreeWarnMB) {
    log("ALERT", "Low free memory", { freeMB, totalMB });
  }
  log("INFO", "Health snapshot", { load, freeMB: Math.round(freeMB), totalMB: Math.round(totalMB) });
}

// Approximate CPU load (0..1) using 1-minute average divided by cores
function cpuLoadApprox() {
  const avg1 = os.loadavg()[0]; // not perfect on Windows, still indicative
  const cores = os.cpus().length || 1;
  return Math.min(1, avg1 / cores);
}

// ---------------- TASK SCHEDULING ----------------
function schedule(name, fn, seconds) {
  // Stagger start to avoid bursts on boot
  setTimeout(() => {
    fn();
    setInterval(fn, seconds * 1000);
  }, Math.floor(Math.random() * 3000));
}

// Example firewall events (simulated)
function simulateTraffic() {
  const samples = ["192.168.1.10", "10.0.0.5", "8.8.8.8"];
  const ip = samples[Math.floor(Math.random() * samples.length)];
  applyFirewallRules(ip);
}

// ---------------- STARTUP ----------------
function start() {
  log("INFO", "Security Agent starting");

  schedule("traffic", simulateTraffic, 30);
  schedule("integrity", checkFileIntegrityOnce, CFG.integrityIntervalSec);
  schedule("process", checkProcesses, CFG.processIntervalSec);
  schedule("ports", checkPorts, CFG.portsIntervalSec);
  schedule("usb", checkUSBDevices, CFG.usbWatchIntervalSec);
  schedule("health", checkHealth, CFG.healthIntervalSec);
  schedule("updates", checkWindowsUpdates, CFG.updatesIntervalSec);

  // Graceful shutdown
  process.on("SIGINT", () => stop("SIGINT"));
  process.on("SIGTERM", () => stop("SIGTERM"));
}

function stop(signal) {
  log("INFO", "Security Agent stopping", { signal });
  process.exit(0);
}

start();

