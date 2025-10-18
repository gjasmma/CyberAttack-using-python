document.getElementById("loginBtn").addEventListener("click", () => {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();
  const result = document.getElementById("result");

  // For now, just simulate
  if (username === "admin" && password === "nosql") {
    result.textContent = "✅ Login successful! Welcome, admin.";
    result.style.color = "lightgreen";
  } else {
    result.textContent = "❌ Invalid credentials.";
    result.style.color = "salmon";
  }
});
