import React, { useState } from "react";
import {
  checkVulnerabilities,
  listIPs,
  respondToIntrusion,
} from "../utils/functions";

interface Props {
  username: string;
}

const Menu: React.FC<Props> = ({ username }) => {
  const [output, setOutput] = useState<string | string[]>("");

  return (
    <div>
      <h2>Welcome, {username}</h2>
      <button onClick={() => setOutput(checkVulnerabilities())}>
        Check Vulnerabilities
      </button>
      <button onClick={() => setOutput(listIPs())}>List IPs</button>
      <button onClick={() => setOutput(respondToIntrusion())}>
        Respond to Intrusion
      </button>

      <div style={{ marginTop: "1rem" }}>
        <strong>Output:</strong>
        <pre>{Array.isArray(output) ? output.join("\n") : output}</pre>
      </div>
    </div>
  );
};

export default Menu;
