import React, { useState } from "react";

function FirewallDashboard() {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<string | null>(null);

  const checkIp = async () => {
    const res = await fetch("http://localhost:4000/api/firewall/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const data = await res.json();
    setResult(`${data.ip} -> ${data.decision}`);
  };

  return (
    <div>
      <input
        type="text"
        placeholder="Enter IP or hostname"
        value={ip}
        onChange={(e) => setIp(e.target.value)}
      />
      <button onClick={checkIp}>Check</button>
      {result && <p>{result}</p>}
    </div>
  );
}

export default FirewallDashboard;
