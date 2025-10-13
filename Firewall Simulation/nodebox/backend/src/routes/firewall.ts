import { Router } from "express";
import { applyFirewallRules } from "../services/firewallService";

const router = Router();

router.post("/check", (req, res) => {
  const { ip } = req.body;
  const decision = applyFirewallRules(ip);
  res.json({ ip, decision });
});

export default router;
