// utils/logger.js

/**
 * A simple console-based logger.
 * In a production environment, you might replace this with a more robust
 * library like Winston or Pino.
 */

const getTimestamp = () => {
  return new Date().toISOString();
};

const logger = {
  info: (message, meta = {}) => {
    console.log(
      `[${getTimestamp()}] [INFO] ${message}`,
      meta ? JSON.stringify(meta, null, 2) : '',
    );
  },
  error: (message, error = null) => {
    console.error(`[${getTimestamp()}] [ERROR] ${message}`);
    if (error) {
      console.error(error);
    }
  },
  warn: (message, meta = {}) => {
    console.warn(
      `[${getTimestamp()}] [WARN] ${message}`,
      meta ? JSON.stringify(meta, null, 2) : '',
    );
  },
  // Add other log levels like 'debug' if needed
  debug: (message, meta = {}) => {
    if (process.env.NODE_ENV === 'development') {
      console.log(
        `[${getTimestamp()}] [DEBUG] ${message}`,
        meta ? JSON.stringify(meta, null, 2) : '',
      );
    }
  },
};

module.exports = logger;
