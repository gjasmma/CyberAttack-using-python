// main.js
const crypto = require("crypto");
const fs = require("fs");

// --- Firewall-like IP blocker ---
const blockedIPs = new Set(["192.168.1.100"]);

function checkIP(ip) {
  if (blockedIPs.has(ip)) {
    logEvent(`Access denied for ${ip}`);
    console.log(`Access denied for: ${ip}`);
    return false;
  }
  logEvent(`Access granted for ${ip}`);
  console.log(`Access granted for: ${ip}`);
  return true;
}

// --- Secure login with hashed passwords ---
const users = {
  alice: crypto.createHash("sha256").update("mypassword").digest("hex"),
};

// Simple rate limiter (max 3 attempts per user per minute)
const loginAttempts = new Map();

function login(username, password) {
  const now = Date.now();
  const attempts = loginAttempts.get(username) || [];
  const recentAttempts = attempts.filter(t => now - t < 60_000);

  if (recentAttempts.length >= 3) {
    logEvent(`Rate limit exceeded for ${username}`);
    console.log("Too many attempts. Try again later.");
    return false;
  }

  const hash = crypto.createHash("sha256").update(password).digest("hex");
  if (users[username] && users[username] === hash) {
    logEvent(`Login successful for ${username}`);
    console.log("Login successful");
    loginAttempts.set(username, []);
    return true;
  }

  recentAttempts.push(now);
  loginAttempts.set(username, recentAttempts);
  logEvent(`Login failed for ${username}`);
  console.log("Login failed");
  return false;
}

// --- Audit logging ---
function logEvent(message) {
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] ${message}\n`;
  fs.appendFileSync("audit.log", entry);
}

// --- Example usage ---
checkIP("195.245.108.162"); // denied
checkIP("10.0.0.5");      // allowed

login("alice", "wrongpass");
login("alice", "wrongpass");
login("alice", "wrongpass");
login("alice", "mypassword"); // should be rate-limited
