const Redis = require("ioredis");
const { rateLimit, bruteForce, redisUrl } = require("../config");
const { info, warn, audit } = require("../logger");

const redis = new Redis(redisUrl);

// Helpers
function key(namespace, id) {
  return `sec:${namespace}:${id}`;
}

async function increment(keyName, ttlSec) {
  const pipeline = redis.pipeline();
  pipeline.incr(keyName);
  pipeline.expire(keyName, ttlSec);
  const [countRes] = await pipeline.exec();
  return countRes[1]; // count
}

// IP rate limiting
async function checkIpRateLimit(ip) {
  const k = key("ip", ip);
  const count = await increment(k, rateLimit.windowSec);
  if (count > rateLimit.maxPerIp) {
    warn("rate_limit_ip_exceeded", { ip, count });
    return { limited: true, reason: "ip_rate_limit" };
  }
  return { limited: false, count };
}

// User login rate limiting
async function checkUserLoginRate(username) {
  const k = key("user_login", username);
  const count = await increment(k, rateLimit.windowSec);
  if (count > rateLimit.maxLoginPerUser) {
    warn("rate_limit_user_exceeded", { username, count });
    return { limited: true, reason: "user_rate_limit" };
  }
  return { limited: false, count };
}

// Brute-force tracking
async function recordFailed(username, ip) {
  const failedKey = key("bf_failed", username);
  const count = await increment(failedKey, bruteForce.lockoutSec);
  const backoffSec = bruteForce.backoffBaseSec * count;

  if (count >= bruteForce.threshold) {
    const lockKey = key("bf_lock", username);
    await redis.set(lockKey, "1", "EX", bruteForce.lockoutSec);
    warn("bf_lockout", { username, ip, count });
  } else {
    info("bf_backoff_hint", { username, ip, count, backoffSec });
  }
  return { count, backoffSec };
}

async function clearFailed(username) {
  await redis.del(key("bf_failed", username));
  await redis.del(key("bf_lock", username));
}

async function isLocked(username) {
  const locked = await redis.get(key("bf_lock", username));
  return !!locked;
}

module.exports = {
  checkIpRateLimit,
  checkUserLoginRate,
  recordFailed,
  clearFailed,
  isLocked,
  redis,
};
