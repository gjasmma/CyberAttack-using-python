export const USERS: Record<string, string> = {
  admin: "1234",
  guest: "guestpass",
};

export function login(username: string, password: string): boolean {
  return USERS[username] === password;
}

export function checkVulnerabilities(): string {
  return "🔍 No real vulnerabilities found (stub).";
}

export function listIPs(): string[] {
  return ["192.168.1.1", "10.0.0.1"];
}

export function respondToIntrusion(): string {
  return "⚠️ Intrusion detected! Responding...";
}
