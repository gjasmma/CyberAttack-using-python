function log(level, message, meta = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta,
  };
  // Console for demo; replace with Bunyan/Winston/Datadog/etc.
  console.log(JSON.stringify(entry));
}

module.exports = {
  info: (msg, meta) => log("info", msg, meta),
  warn: (msg, meta) => log("warn", msg, meta),
  error: (msg, meta) => log("error", msg, meta),
  audit: (msg, meta) => log("audit", msg, meta),
};
