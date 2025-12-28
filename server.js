import express from "express";
import { V2 } from "paseto";
import nacl from "tweetnacl";
import dotenv from "dotenv";

dotenv.config();

/**
 * Generate an Ed25519 key pair with tweetnacl
 */
console.log("🟡 Generating Ed25519 key pair (v2.public) ...");
const keyPair = nacl.sign.keyPair(); // Uint8Arrays
const privateKey = Buffer.from(keyPair.secretKey);
const publicKey = Buffer.from(keyPair.publicKey);
console.log("✅ Keys ready, starting Express...");

const app = express();
app.use(express.json());

// issue token
app.post("/token", async (req, res) => {
  try {
    const payload = {
      userId: req.body.userId,
      role: req.body.role,
      issuedAt: new Date().toISOString(),
    };

    const token = await V2.sign(payload, privateKey, {
      issuer: "my-app",
      audience: "users",
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (err) {
    console.error("❌ Token generation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// verify token
app.post("/verify", async (req, res) => {
  try {
    const { token } = req.body;
    const payload = await V2.verify(token, publicKey, {
      issuer: "my-app",
      audience: "users",
    });
    res.json({ valid: true, payload });
  } catch (err) {
    console.error("❌ Verification failed:", err);
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));