import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

// Make sure your index.html has <div id="root"></div>
const container = document.getElementById("root");

if (container) {
  const root = ReactDOM.createRoot(container);
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
} else {
  console.error(
    "❌ Root container not found. Did you forget <div id='root'></div> in index.html?"
  );
}
