// backend/server.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

app.use(cors());
app.use(express.json());

const allowedPorts = [80, 443, 22, 8080];
const suspiciousPorts = [666, 1337, 31337];
let firewallEnabled = true;
let vulnerabilities = ["Open port 22", "Weak encryption"];

let scanStats = {
  secure: 0,
  suspicious: 0,
  unknown: 0,
};

io.on("connection", (socket) => {
  console.log("Client connected");
});

app.post("/check-port", (req, res) => {
  const port = parseInt(req.body.port, 10);
  if (isNaN(port)) {
    return res
      .status(400)
      .json({ status: "error", message: "Invalid port number." });
  }

  let category = "unknown";
  if (allowedPorts.includes(port)) {
    category = "secure";
    scanStats.secure++;
  } else if (suspiciousPorts.includes(port)) {
    category = "suspicious";
    scanStats.suspicious++;
    io.emit("alert", {
      type: "suspicious",
      message: `Suspicious port ${port} scanned!`,
    });
  } else {
    scanStats.unknown++;
  }

  res.json({
    status: category,
    message:
      category === "secure"
        ? "Port is secure. Access granted."
        : category === "suspicious"
        ? "Suspicious port detected! Potential cyber attack."
        : "Port not recognized.",
  });
});

app.post("/patch-firewall", (req, res) => {
  if (firewallEnabled) {
    vulnerabilities = vulnerabilities.filter((v) => v !== "Open port 22");
    return res.json({
      status: "patched",
      message: "Firewall upgraded and vulnerabilities patched.",
      vulnerabilities,
    });
  } else {
    return res.status(403).json({
      status: "error",
      message: "Firewall is disabled.",
    });
  }
});

app.get("/firewall-status", (req, res) => {
  res.json({ firewallEnabled, vulnerabilities });
});

app.get("/scan-stats", (req, res) => {
  res.json(scanStats);
});

server.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);
