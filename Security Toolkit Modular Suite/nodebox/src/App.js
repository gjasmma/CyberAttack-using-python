// public/app.js
const state = {
  user: null,
  plugins: [],
  current: null,
};

async function fetchPlugins() {
  const res = await fetch("/api/plugins");
  state.plugins = await res.json();
  renderPluginList();
}

function renderPluginList() {
  const nav = document.getElementById("plugin-list");
  nav.innerHTML = "";
  state.plugins.forEach((p) => {
    const item = document.createElement("div");
    item.className = "item";
    item.dataset.id = p.id;
    item.innerHTML = `
      <div class="icon">${p.icon}</div>
      <div class="text">
        <div class="title">${p.name}</div>
        <div class="sub">${p.description}</div>
      </div>
    `;
    item.addEventListener("click", () => selectPlugin(p.id));
    nav.appendChild(item);
  });
}

function selectPlugin(id) {
  state.current = state.plugins.find((p) => p.id === id);
  document.querySelectorAll(".nav .item").forEach((el) => {
    el.classList.toggle("active", el.dataset.id === id);
  });

  document.getElementById("panel-title").textContent = state.current.name;
  document.getElementById("panel-desc").textContent = state.current.description;

  const form = document.getElementById("plugin-form");
  form.classList.remove("hidden");
  form.innerHTML = buildFormForPlugin(state.current.id);
  document.getElementById(
    "results"
  ).innerHTML = `<div class="placeholder">Ready to run ${state.current.name}.</div>`;

  form.addEventListener("submit", onRunPlugin);
}

function buildFormForPlugin(id) {
  switch (id) {
    case "password-strength":
      return `
        <div class="form-row">
          <label>Password</label>
          <input type="password" name="password" placeholder="Enter password to evaluate" />
        </div>
        <button class="btn primary" type="submit">Run</button>
      `;
    case "file-integrity":
      return `
        <div class="form-row">
          <label>File path</label>
          <input type="text" name="filePath" placeholder="/path/to/file" />
        </div>
        <div class="form-row">
          <label>Expected SHA-256 (optional)</label>
          <input type="text" name="expectedHash" placeholder="abcdef..." />
        </div>
        <button class="btn primary" type="submit">Run</button>
      `;
    case "malware-scan":
    case "intrusion-detect":
    default:
      return `<button class="btn primary" type="submit">Run</button>`;
  }
}

async function onRunPlugin(e) {
  e.preventDefault();
  const form = e.target;
  const data = Object.fromEntries(new FormData(form).entries());

  const res = await fetch(`/api/plugins/${state.current.id}/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });

  const json = await res.json();
  const container = document.getElementById("results");
  if (!json.ok) {
    container.innerHTML = `<div class="result-card"><strong>Error:</strong> ${json.error}</div>`;
    return;
  }
  container.innerHTML = renderResult(json.result);
}

function renderResult(result) {
  // Pretty-print with small helpers
  const pre = `<pre class="result-card">${escapeHTML(
    JSON.stringify(result, null, 2)
  )}</pre>`;
  return pre;
}

function escapeHTML(str) {
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
  return str.replace(/[&<>"]/g, (ch) => map[ch]);
}

// Login modal logic
const modal = document.getElementById("modal");
document.getElementById("login-btn").addEventListener("click", () => {
  modal.classList.remove("hidden");
});
document.getElementById("modal-cancel").addEventListener("click", () => {
  modal.classList.add("hidden");
});
document.getElementById("modal-submit").addEventListener("click", async () => {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const json = await res.json();
  if (json.ok) {
    state.user = json.user;
    document.getElementById(
      "session-info"
    ).textContent = `${json.user.name} (${json.user.role})`;
    modal.classList.add("hidden");
  } else {
    alert("Login failed");
  }
});

// Boot
fetchPlugins();
