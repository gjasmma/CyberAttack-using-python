module.exports = {
  jwtSecret: process.env.JWT_SECRET || "replace-with-strong-secret",
  jwtTtlSec: 60 * 5, // 5 minutes

  bcryptRounds: 12,

  // Redis
  redisUrl: process.env.REDIS_URL || "redis://localhost:6379",

  // Rate limiting
  rateLimit: {
    windowSec: 60, // 1 minute window
    maxPerIp: 100, // requests per IP per window
    maxLoginPerUser: 10, // login attempts per user per window
  },

  // Brute force
  bruteForce: {
    threshold: 5, // failed attempts before lock
    lockoutSec: 15 * 60, // 15 minutes
    backoffBaseSec: 5, // increases with attempts
  },
};
