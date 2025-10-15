// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();

// Middleware
app.use(express.json()); // parse JSON bodies
app.use(express.static(path.join(__dirname, "public"))); // serve front-end

// --- Fake user database ---
const USERS = {
  admin: "1234",
  guest: "guestpass",
};

// --- Login route ---
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (USERS[username] && USERS[username] === password) {
    res.json({
      ok: true,
      user: {
        name: username,
        role: username === "admin" ? "admin" : "guest",
      },
    });
  } else {
    res.status(401).json({ ok: false, error: "Invalid credentials" });
  }
});

// --- Plugin loader ---
function loadPlugins() {
  const dir = path.join(__dirname, "plugins");
  if (!fs.existsSync(dir)) return [];
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".js"));
  return files
    .map((file) => {
      const mod = require(path.join(dir, file));
      if (!mod.id || !mod.name || !mod.run) {
        console.warn(`⚠️ Plugin ${file} missing id/name/run — skipped`);
        return null;
      }
      return mod;
    })
    .filter(Boolean);
}

const plugins = loadPlugins();

// --- List plugins ---
app.get("/api/plugins", (req, res) => {
  res.json(
    plugins.map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description || "",
      icon: p.icon || "🛡️",
    }))
  );
});

// --- Run plugin ---
app.post("/api/plugins/:id/run", async (req, res) => {
  const plugin = plugins.find((p) => p.id === req.params.id);
  if (!plugin)
    return res.status(404).json({ ok: false, error: "Plugin not found" });

  try {
    const result = await plugin.run(req.body || {});
    res.json({ ok: true, result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Plugin execution error" });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Security Toolkit running at http://localhost:${PORT}`);
});
