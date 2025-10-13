# 🔥 Firewall Simulation Dashboard

A full‑stack **TypeScript + Node.js + React** project that simulates firewall behavior with a professional, user‑friendly dashboard.  
It demonstrates **ethical, privacy‑first security principles** aligned with modern best practices.

---

## ✨ Features

- **Backend (Node.js + Express + TypeScript)**
  - Rule‑based firewall engine (allow/block lists).
  - API endpoint: `POST /api/firewall/check` → returns decision for given IP/hostname.
  - Easily extendable with new rules (rate limiting, honeypot, anomaly detection).

- **Frontend (React + Vite + TypeScript)**
  - Clean, professional UI styled with CSS.
  - Input field to test IPs/hostnames.
  - Real‑time result display (green for ALLOW ✅, red for BLOCK 🚫).
  - **Traffic log table** with timestamps.
  - **Persistence**: previous trackings stored in `localStorage`.
  - **Clear Log** button to reset history.
  - Loading state while checking.

---

## 📂 Project Structure

🛡️ Example Usage
Request

bash
POST http://localhost:4000/api/firewall/check
Content-Type: application/json

{ "ip": "192.168.1.1" }
Response

json
{ "ip": "192.168.1.1", "decision": "BLOCK" }
🎨 UI Preview
Enter an IP/hostname → click Check.

Result displayed instantly:

✅ Green card → ALLOW

🚫 Red card → BLOCK

Traffic log records all checks with timestamps.

Log persists across reloads.

🔮 Future Enhancements
Rate limiting simulation.

Honeypot trap detection.

Anomaly detection with moving averages.

Export logs as CSV/JSON.

Dark mode toggle.

📜 License
MIT License — Contact Author for Details . Gidon Joseph.
