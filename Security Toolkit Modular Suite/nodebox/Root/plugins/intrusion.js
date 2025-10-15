// plugins/intrusion.js
const os = require("os");

module.exports = {
  id: "intrusion-detect",
  name: "Intrusion Detection",
  icon: "🚨",
  description: "Simulate detection of suspicious network activity.",
  run: async () => {
    const nets = os.networkInterfaces();
    const ips = [];
    Object.values(nets).forEach((ifaces) =>
      ifaces.forEach((i) => {
        if (i.family === "IPv4" && !i.internal) ips.push(i.address);
      })
    );
    // Simulated alert
    return {
      localIPs: ips,
      alert: {
        port: 22,
        action: "block",
        severity: "medium",
        note: "Simulated SSH brute-force attempt",
      },
    };
  },
};
