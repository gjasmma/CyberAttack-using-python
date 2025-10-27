// src/App.js
import React, { useState, useEffect } from "react";
import io from "socket.io-client";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const socket = io("http://localhost:3000");
const API = "http://localhost:3000";

export default function App() {
  const [port, setPort] = useState("");
  const [portResult, setPortResult] = useState("");
  const [patchResult, setPatchResult] = useState("");
  const [statusResult, setStatusResult] = useState("");
  const [scanStats, setScanStats] = useState({
    secure: 0,
    suspicious: 0,
    unknown: 0,
  });

  useEffect(() => {
    fetch(`${API}/scan-stats`)
      .then((res) => res.json())
      .then((data) => setScanStats(data));

    socket.on("alert", (data) => {
      alert(`⚠️ ${data.message}`);
      fetch(`${API}/scan-stats`)
        .then((res) => res.json())
        .then((data) => setScanStats(data));
    });

    return () => socket.off("alert");
  }, []);

  const checkPort = async () => {
    const res = await fetch(`${API}/check-port`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ port }),
    });
    const data = await res.json();
    setPortResult(data.message);
    fetch(`${API}/scan-stats`)
      .then((res) => res.json())
      .then((data) => setScanStats(data));
  };

  const patchFirewall = async () => {
    const res = await fetch(`${API}/patch-firewall`, { method: "POST" });
    const data = await res.json();
    setPatchResult(data.message);
  };

  const getFirewallStatus = async () => {
    const res = await fetch(`${API}/firewall-status`);
    const data = await res.json();
    setStatusResult(
      `Firewall: ${
        data.firewallEnabled ? "Enabled" : "Disabled"
      }, Vulnerabilities: ${data.vulnerabilities.join(", ")}`
    );
  };

  const chartData = {
    labels: ["Secure", "Suspicious", "Unknown"],
    datasets: [
      {
        label: "Port Scan Attempts",
        data: [scanStats.secure, scanStats.suspicious, scanStats.unknown],
        backgroundColor: ["#28a745", "#dc3545", "#6c757d"],
      },
    ],
  };

  return (
    <div className="container">
      <h1>🛡️ Network Security Dashboard</h1>

      <div className="section">
        <h2>🔍 Port Scanner</h2>
        <input
          type="number"
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="Enter port number"
        />
        <button onClick={checkPort}>Check Port</button>
        <p>{portResult}</p>
      </div>

      <div className="section">
        <h2>🧰 Firewall Patch</h2>
        <button onClick={patchFirewall}>Patch Firewall</button>
        <p>{patchResult}</p>
      </div>

      <div className="section">
        <h2>📋 Firewall Status</h2>
        <button onClick={getFirewallStatus}>Get Firewall Status</button>
        <p>{statusResult}</p>
      </div>

      <div className="section">
        <h2>📊 Port Scan Chart</h2>
        <Bar data={chartData} />
      </div>
    </div>
  );
}
