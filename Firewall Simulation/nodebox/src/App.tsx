import React, { useState, useEffect } from "react";
import "./styles.css";

interface FirewallResult {
  ip: string;
  decision: string;
  timestamp: string;
}

function App() {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<FirewallResult | null>(null);
  const [log, setLog] = useState<FirewallResult[]>([]);
  const [loading, setLoading] = useState(false);

  // Load previous trackings from localStorage on mount
  useEffect(() => {
    const savedLog = localStorage.getItem("firewallLog");
    if (savedLog) {
      setLog(JSON.parse(savedLog));
    }
  }, []);

  // Save log to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem("firewallLog", JSON.stringify(log));
  }, [log]);

  const checkIp = async () => {
    if (!ip) return;
    setLoading(true);
    try {
      const res = await fetch("http://localhost:4000/api/firewall/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      const data = await res.json();
      const entry: FirewallResult = {
        ip: data.ip,
        decision: data.decision,
        timestamp: new Date().toLocaleString(),
      };
      setResult(entry);
      setLog([entry, ...log]); // prepend new entry
    } catch (err) {
      console.error("Error contacting backend:", err);
    } finally {
      setLoading(false);
    }
  };

  const clearLog = () => {
    setLog([]);
    setResult(null);
    localStorage.removeItem("firewallLog");
  };

  return (
    <div className="dashboard">
      <h1>🔥 Firewall Simulation 🔥</h1>
      <div className="input-group">
        <input
          type="text"
          placeholder="Enter IP or hostname"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
        <button onClick={checkIp} disabled={loading}>
          {loading ? "Checking..." : "Check"}
        </button>
        <button className="clear-btn" onClick={clearLog}>
          Clear Log
        </button>
      </div>

      {result && (
        <div className={`result ${result.decision.toLowerCase()}`}>
          {result.ip} → {result.decision}
        </div>
      )}

      <h2>Traffic Log</h2>
      {log.length === 0 ? (
        <p className="empty-log">No traffic checked yet.</p>
      ) : (
        <table className="log-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP / Hostname</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {log.map((entry, idx) => (
              <tr key={idx} className={entry.decision.toLowerCase()}>
                <td>{entry.timestamp}</td>
                <td>{entry.ip}</td>
                <td>{entry.decision}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default App;
