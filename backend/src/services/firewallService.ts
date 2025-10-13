import { Rule, Action } from "../models/rule";

const rules: Rule[] = [
  {
    name: "Block local gateway",
    regex: /^192\.168\.1\.1$/,
    action: Action.BLOCK,
  },
  { name: "Block office router", regex: /^10\.0\.0\.1$/, action: Action.BLOCK },
  { name: "Block hackerserver", regex: /^hackerserver$/, action: Action.BLOCK },
  {
    name: "Allow corp subnet",
    regex: /^10\.0\.0\.(?!1$)\d{1,3}$/,
    action: Action.ALLOW,
  },
];

export function applyFirewallRules(ip: string): Action {
  for (const rule of rules) {
    if (rule.regex.test(ip)) {
      return rule.action;
    }
  }
  return Action.ALLOW; // default
}
