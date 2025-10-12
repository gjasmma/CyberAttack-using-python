class SecureServer {
  constructor() {
    this.securityLevel = 5;
    this.test = false;
    this.ftp = false;
  }

  checkSecurityLevel() {
    let levelDescription = "";
    switch (this.securityLevel) {
      case 5:
        levelDescription = "Very High";
        break;
      case 4:
        levelDescription = "High";
        break;
      case 3:
        levelDescription = "Medium";
        break;
      case 2:
        levelDescription = "Low";
        break;
      default:
        levelDescription = "Unknown";
    }
    return `Server security is ${levelDescription}.`;
  }

  run() {
    console.log("Server is running...");
  }
}

// Example login function
function login(username, password) {
  const validUser = "admin";
  const validPass = "1234";

  if (username === validUser && password === validPass) {
    return true;
  }
  return false;
}

// Example usage
const server = new SecureServer();
console.log(server.checkSecurityLevel()); // "Server security is Very High."
console.log(login("admin", "1234"));      // true
