/**
 * Seed script: create the PrecedentLab admin user + API key in cal.diy,
 * and install the google-calendar App row that GCalService reads at
 * OAuth time (so /v2/oauth/connect/google-calendar can find credentials).
 *
 * Required env:
 *   DATABASE_URL              - postgres connection string
 *   CALCOM_ADMIN_API_KEY_HASH - SHA256 of stripped API key suffix
 *
 * Optional env (omit to skip the Google Calendar app seed):
 *   GOOGLE_API_CREDENTIALS    - JSON from Google Cloud Console. Accepts
 *                               the {"web": {...}} envelope or just
 *                               {"client_id": "...", "client_secret": "..."}
 */

const { Client } = require("pg");
const { randomUUID } = require("crypto");

const ADMIN_EMAIL = "admin-calcom@precedentlab.com";
const ADMIN_USERNAME = "pl-admin";
const HASHED_KEY = process.env.CALCOM_ADMIN_API_KEY_HASH;

function extractGoogleKeys(raw) {
  if (!raw) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.warn("GOOGLE_API_CREDENTIALS is not valid JSON; skipping Google Calendar app seed.");
    return null;
  }
  const inner = parsed.web || parsed.installed || parsed;
  if (!inner.client_id || !inner.client_secret) {
    console.warn("GOOGLE_API_CREDENTIALS missing client_id/client_secret; skipping Google Calendar app seed.");
    return null;
  }
  return { client_id: inner.client_id, client_secret: inner.client_secret };
}

async function main() {
  if (!HASHED_KEY) throw new Error("CALCOM_ADMIN_API_KEY_HASH env var is required");

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  try {
    // uuid column: NOT NULL, no db-level default (Prisma-level uuid() default)
    const uuid = randomUUID();
    const userRes = await client.query(
      `INSERT INTO "users" (email, username, name, uuid, role, "completedOnboarding", "emailVerified", "timeZone", "weekStart")
       VALUES ($1, $2, $3, $4, 'ADMIN', true, NOW(), 'America/New_York', 'Sunday')
       ON CONFLICT (email) DO UPDATE
         SET role = 'ADMIN', username = $2, "completedOnboarding" = true
       RETURNING id, email`,
      [ADMIN_EMAIL, ADMIN_USERNAME, "PrecedentLab Admin", uuid]
    );
    const userId = userRes.rows[0].id;
    console.log("Admin user upserted: id=" + userId + " email=" + userRes.rows[0].email);

    // Check if API key already exists
    const existing = await client.query(
      `SELECT id FROM "ApiKey" WHERE "hashedKey" = $1`,
      [HASHED_KEY]
    );
    if (existing.rows.length > 0) {
      console.log("API key already exists: id=" + existing.rows[0].id);
    } else {
      // ApiKey.id is a cuid string — Prisma-level default, so we must provide it
      const apiKeyId = randomUUID();
      const keyRes = await client.query(
        `INSERT INTO "ApiKey" (id, "userId", "hashedKey", note, "expiresAt") VALUES ($1, $2, $3, $4, NULL) RETURNING id`,
        [apiKeyId, userId, HASHED_KEY, "PrecedentLab pl-api admin key"]
      );
      console.log("API key created: id=" + keyRes.rows[0].id);
    }

    // ── Google Calendar app row ─────────────────────────────────────────
    const googleKeys = extractGoogleKeys(process.env.GOOGLE_API_CREDENTIALS);
    if (googleKeys) {
      await client.query(
        `INSERT INTO "App" (slug, "dirName", keys, categories, enabled, "updatedAt")
         VALUES ('google-calendar', 'googlecalendar', $1::jsonb, ARRAY['calendar']::"AppCategories"[], true, NOW())
         ON CONFLICT (slug) DO UPDATE
           SET keys = EXCLUDED.keys, enabled = true, "updatedAt" = NOW()`,
        [JSON.stringify(googleKeys)],
      );
      console.log("Google Calendar app installed (slug=google-calendar, enabled=true).");
    } else {
      console.log("Skipped Google Calendar app seed (GOOGLE_API_CREDENTIALS not provided).");
    }

    console.log("Seed complete.");
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
