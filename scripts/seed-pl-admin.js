/**
 * Seed script: create the PrecedentLab admin user + API key in cal.diy.
 * Run via Cloud Run job after prisma migrate deploy.
 *
 * Usage:
 *   node scripts/seed-pl-admin.js
 *
 * Required env:
 *   DATABASE_URL            - postgres connection string
 *   CALCOM_ADMIN_API_KEY_HASH - SHA256 of stripped API key suffix (no "cal_" prefix)
 */

// The Prisma client is generated to packages/prisma/generated/prisma during Docker build
const { PrismaClient } = require("../packages/prisma/generated/prisma");

const prisma = new PrismaClient();

const ADMIN_EMAIL = "admin-calcom@precedentlab.com";
const ADMIN_USERNAME = "pl-admin";
const HASHED_KEY = process.env.CALCOM_ADMIN_API_KEY_HASH;

async function main() {
  if (!HASHED_KEY) {
    throw new Error("CALCOM_ADMIN_API_KEY_HASH env var is required");
  }

  // Upsert admin user
  const user = await prisma.user.upsert({
    where: { email: ADMIN_EMAIL },
    update: { role: "ADMIN", username: ADMIN_USERNAME, completedOnboarding: true },
    create: {
      email: ADMIN_EMAIL,
      username: ADMIN_USERNAME,
      name: "PrecedentLab Admin",
      role: "ADMIN",
      completedOnboarding: true,
      emailVerified: new Date(),
      timeZone: "America/New_York",
      weekStart: "Sunday",
    },
  });

  console.log(`Admin user upserted: id=${user.id} email=${user.email}`);

  // Upsert API key (never expires)
  const existing = await prisma.apiKey.findUnique({ where: { hashedKey: HASHED_KEY } });
  if (existing) {
    console.log(`API key already exists: id=${existing.id}`);
  } else {
    const apiKey = await prisma.apiKey.create({
      data: {
        userId: user.id,
        hashedKey: HASHED_KEY,
        note: "PrecedentLab pl-api admin key",
        expiresAt: null,
      },
    });
    console.log(`API key created: id=${apiKey.id}`);
  }

  console.log("Seed complete.");
}

main()
  .catch((err) => {
    console.error("Seed failed:", err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
