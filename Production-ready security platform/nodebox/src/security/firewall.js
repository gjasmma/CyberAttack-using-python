const { info, warn, audit } = require("../logger");
const { isSuspiciousIP } = require("./ipDetector");

const allowList = new Set(["192.168.1.1", "10.0.0.1"]);
const blockList = new Set(["hackerserver"]); // may be host/IP

function applyFirewallRules(ip) {
  if (allowList.has(ip)) {
    audit("traffic_allowed", { ip });
    return { allowed: true, reason: "allowlist" };
  }
  if (blockList.has(ip) || isSuspiciousIP(ip, allowList)) {
    audit("traffic_blocked", {
      ip,
      reason: blockList.has(ip) ? "blocklist" : "suspicious",
    });
    return {
      allowed: false,
      reason: blockList.has(ip) ? "blocklist" : "suspicious",
    };
  }
  audit("traffic_blocked", { ip, reason: "default_deny" });
  return { allowed: false, reason: "default_deny" };
}

function addToAllowList(ip, role) {
  if (role !== "superuser") {
    warn("firewall_update_denied", { ip, role });
    return false;
  }
  allowList.add(ip);
  info("allowlist_add", { ip });
  return true;
}

function addToBlockList(ip, role) {
  if (role !== "superuser") {
    warn("firewall_update_denied", { ip, role });
    return false;
  }
  blockList.add(ip);
  info("blocklist_add", { ip });
  return true;
}

module.exports = {
  applyFirewallRules,
  addToAllowList,
  addToBlockList,
};
