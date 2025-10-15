// plugins/integrity.js
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

module.exports = {
  id: "file-integrity",
  name: "File Integrity",
  icon: "📂",
  description: "Compute SHA-256 of a file and compare with expected hash.",
  run: async ({ filePath, expectedHash }) => {
    if (!filePath) return { error: "filePath is required" };
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) return { error: "File not found" };

    const data = fs.readFileSync(resolved);
    const hash = crypto.createHash("sha256").update(data).digest("hex");
    const matches = expectedHash ? hash === expectedHash.toLowerCase() : null;
    return { file: resolved, hash, matches };
  },
};
