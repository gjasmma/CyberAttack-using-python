import express from "express";
import firewallRoutes from "./routes/firewall";

const app = express();
app.use(express.json());

app.use("/api/firewall", firewallRoutes);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
