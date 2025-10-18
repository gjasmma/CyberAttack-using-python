const express = require("express");
const path = require("path");
const { demo } = require("./src/app");

const app = express();
const PORT = 3000;

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  demo(); // run backend demo logic
});
