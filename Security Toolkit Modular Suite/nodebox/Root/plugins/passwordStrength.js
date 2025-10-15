// plugins/passwordStrength.js
module.exports = {
  id: "password-strength",
  name: "Password Strength",
  icon: "🔑",
  description: "Evaluate password strength with simple heuristics.",
  run: async ({ password }) => {
    if (!password) return { error: "No password provided" };
    let score = 0;
    const checks = {
      length: password.length >= 12,
      digit: /\d/.test(password),
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      symbol: /[!@#$%^&*()\-_=+[\]{};:,.<>/?]/.test(password),
      common: /(password|1234|qwerty|letmein)/i.test(password),
    };
    score += checks.length ? 2 : 0;
    score += checks.digit ? 1 : 0;
    score += checks.upper ? 1 : 0;
    score += checks.lower ? 1 : 0;
    score += checks.symbol ? 2 : 0;
    if (checks.common) score = Math.max(0, score - 3);

    const levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"];
    const level = levels[Math.min(Math.floor(score / 2), levels.length - 1)];
    return { level, score, checks };
  },
};
