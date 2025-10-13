import React, { useState } from "react";
import LoginForm from "./LoginForm";
import Menu from "./Menu";

const App: React.FC = () => {
  const [user, setUser] = useState<string | null>(null);

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial" }}>
      {!user ? (
        <LoginForm onLoginSuccess={setUser} />
      ) : (
        <Menu username={user} />
      )}
    </div>
  );
};

export default App;
