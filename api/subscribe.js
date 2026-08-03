// Subscription endpoint for binayahestate.com.
//
// Writes to the shared `marketreportsubscriptions` collection using the SAME
// field-level AES-256-GCM encryption + HMAC blind index as binayah-properties,
// so signups appear in the existing Leads / Newsletter dashboard automatically.
//
// Wire format matches src/lib/encryption.ts:  enc:<kid>:<base64(iv|tag|ct)>
// Env required: MONGODB_URI, ENCRYPTION_KEY (64-hex), HMAC_KEY (64-hex),
//               ENCRYPTION_KEYS_OLD (optional, comma-separated retired hex keys).

import { MongoClient } from "mongodb";
import { createCipheriv, createHmac, createHash, randomBytes } from "crypto";

const DB = "binayah_web_new_dev";
const COLLECTION = "marketreportsubscriptions";
const SOURCE = "binayahestate-landing";
const ENC_PREFIX = "enc:";

// ── crypto helpers (mirror of the main app) ──────────────────────────────────
function keyBuf(hex) {
  if (!hex || hex.length !== 64) throw new Error("key must be 64-char hex");
  return Buffer.from(hex, "hex");
}
const PRIMARY = keyBuf(process.env.ENCRYPTION_KEY || "");
const KID = createHash("sha256").update(PRIMARY).digest("hex").slice(0, 8);
const HMAC = keyBuf(process.env.HMAC_KEY || "");

function encrypt(plaintext) {
  if (!plaintext) return undefined;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", PRIMARY, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENC_PREFIX}${KID}:${Buffer.concat([iv, tag, ct]).toString("base64")}`;
}
function fieldHash(value) {
  if (!value) return undefined;
  return createHmac("sha256", HMAC).update(String(value).toLowerCase().trim()).digest("hex");
}

// ── cached Mongo connection (survives warm invocations) ──────────────────────
let clientPromise;
function getClient() {
  if (!clientPromise) {
    clientPromise = new MongoClient(process.env.MONGODB_URI, {
      maxPoolSize: 3,
      serverSelectionTimeoutMS: 8000,
    }).connect();
  }
  return clientPromise;
}

// ── best-effort per-IP throttle (warm-instance memory only) ──────────────────
const hits = new Map();
function throttled(ip) {
  const now = Date.now();
  const rec = hits.get(ip) || { n: 0, t: now };
  if (now - rec.t > 60_000) { rec.n = 0; rec.t = now; }
  rec.n += 1;
  hits.set(ip, rec);
  return rec.n > 8; // >8 signups/min from one IP
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};

  const email = String(body.email || "").trim().toLowerCase();
  const name = String(body.name || "").trim().slice(0, 120);
  const phoneRaw = String(body.phone || "").trim();
  const phone = phoneRaw ? phoneRaw.replace(/[\s\-.()]/g, "") : "";
  const honeypot = String(body.company || "").trim();

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailOk) return res.status(400).json({ ok: false, error: "A valid email is required." });

  // Honeypot: bots fill hidden fields. Accept silently, store nothing.
  if (honeypot) return res.status(200).json({ ok: true, already: false });

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (throttled(ip)) return res.status(429).json({ ok: false, error: "Too many requests. Please try again shortly." });

  try {
    const client = await getClient();
    const col = client.db(DB).collection(COLLECTION);
    const emailH = fieldHash(email);
    const now = new Date();

    const setFields = {
      email: encrypt(email),
      emailH,
      updatedAt: now,
    };
    if (name) setFields.name = encrypt(name);
    if (phone) { setFields.phone = encrypt(phone); setFields.phoneH = fieldHash(phone); }

    const result = await col.updateOne(
      { emailH },
      {
        $set: setFields,
        $setOnInsert: {
          source: SOURCE,
          status: "new",
          intents: ["property-alerts"],
          confirmed: false,
          createdAt: now,
        },
      },
      { upsert: true }
    );

    const already = result.upsertedCount === 0;
    return res.status(200).json({ ok: true, already });
  } catch (err) {
    console.error("[subscribe] failed:", err && err.message);
    return res.status(500).json({ ok: false, error: "Could not save your subscription. Please try again." });
  }
}
