/**
 * Configuration Loading
 *
 * Loads config from (in order of precedence):
 * 1. CLI arguments (highest)
 * 2. Environment variables (JSS_*)
 * 3. Config file (config.json)
 * 4. Defaults (lowest)
 */

import fs from 'fs-extra';
import path from 'path';

/**
 * Default configuration values
 */
export const defaults = {
  // Server
  port: 4443,
  host: '0.0.0.0',
  root: './data',

  // SSL
  sslKey: null,
  sslCert: null,

  // Features
  multiuser: true,
  conneg: false,
  notifications: false,

  // Identity Provider
  idp: false,
  idpIssuer: null,

  // Subdomain mode (XSS protection)
  subdomains: false,
  baseDomain: null,

  // Mashlib data browser
  mashlib: false,
  mashlibCdn: false,
  mashlibVersion: '2.0.0',
  mashlibModule: false,

  // Git HTTP backend
  git: false,

  // Nostr relay
  nostr: false,
  nostrPath: '/relay',
  nostrMaxEvents: 1000,

  // WebRTC signaling
  webrtc: false,
  webrtcPath: '/.webrtc',

  // Terminal (WebSocket shell access)
  terminal: false,

  // Tunnel (decentralized ngrok)
  tunnel: false,
  tunnelPath: '/.tunnel',

  // ActivityPub federation
  activitypub: false,
  apUsername: 'me',
  apDisplayName: null,
  apSummary: null,
  apNostrPubkey: null,

  // Invite-only registration
  inviteOnly: false,

  // Single-user mode (personal pod server)
  singleUser: false,
  singleUserName: 'me',
  // Initial IDP password seeded on first single-user pod creation. If
  // unset and --idp is enabled, the server prompts on a TTY or logs a
  // warning and continues startup on non-TTY (so the pod is created but
  // is not yet loggable until a password is set).
  singleUserPassword: null,

  // WebID-TLS client certificate authentication
  webidTls: false,

  // Storage quota (bytes) - 50MB default
  defaultQuota: 50 * 1024 * 1024,

  // Public mode - skip WAC, allow unauthenticated access
  public: false,

  // Read-only mode - disable PUT/DELETE/PATCH
  readOnly: false,

  // Live reload - inject script to auto-refresh browser on file changes
  liveReload: false,

  // HTTP 402 paid access
  pay: false,
  payCost: 1,
  payMempoolUrl: 'https://mempool.space/testnet4',
  payAddress: null,
  payToken: null,
  payRate: 1,
  payChains: null,  // comma-separated chain IDs, e.g. "tbtc3,tbtc4"

  // MongoDB-backed /db/ route
  mongo: false,
  mongoUrl: 'mongodb://localhost:27017',
  mongoDatabase: 'solid',

  // Logging
  logger: true,
  quiet: false,
  logLevel: 'info',

  // Paths
  configPath: './.jss',
};

/**
 * Map of environment variable names to config keys
 */
const envMap = {
  JSS_PORT: 'port',
  JSS_HOST: 'host',
  JSS_ROOT: 'root',
  JSS_SSL_KEY: 'sslKey',
  JSS_SSL_CERT: 'sslCert',
  JSS_MULTIUSER: 'multiuser',
  JSS_CONNEG: 'conneg',
  JSS_NOTIFICATIONS: 'notifications',
  JSS_QUIET: 'quiet',
  JSS_LOG_LEVEL: 'logLevel',
  JSS_CONFIG_PATH: 'configPath',
  JSS_IDP: 'idp',
  JSS_IDP_ISSUER: 'idpIssuer',
  JSS_SUBDOMAINS: 'subdomains',
  JSS_BASE_DOMAIN: 'baseDomain',
  JSS_MASHLIB: 'mashlib',
  JSS_MASHLIB_CDN: 'mashlibCdn',
  JSS_MASHLIB_VERSION: 'mashlibVersion',
  JSS_MASHLIB_MODULE: 'mashlibModule',
  JSS_GIT: 'git',
  JSS_NOSTR: 'nostr',
  JSS_NOSTR_PATH: 'nostrPath',
  JSS_NOSTR_MAX_EVENTS: 'nostrMaxEvents',
  JSS_WEBRTC: 'webrtc',
  JSS_WEBRTC_PATH: 'webrtcPath',
  JSS_TERMINAL: 'terminal',
  JSS_TUNNEL: 'tunnel',
  JSS_TUNNEL_PATH: 'tunnelPath',
  JSS_ACTIVITYPUB: 'activitypub',
  JSS_AP_USERNAME: 'apUsername',
  JSS_AP_DISPLAY_NAME: 'apDisplayName',
  JSS_AP_SUMMARY: 'apSummary',
  JSS_AP_NOSTR_PUBKEY: 'apNostrPubkey',
  JSS_INVITE_ONLY: 'inviteOnly',
  JSS_SINGLE_USER: 'singleUser',
  JSS_SINGLE_USER_NAME: 'singleUserName',
  JSS_SINGLE_USER_PASSWORD: 'singleUserPassword',
  JSS_WEBID_TLS: 'webidTls',
  JSS_DEFAULT_QUOTA: 'defaultQuota',
  JSS_PUBLIC: 'public',
  JSS_READ_ONLY: 'readOnly',
  JSS_LIVE_RELOAD: 'liveReload',
  JSS_PAY: 'pay',
  JSS_PAY_COST: 'payCost',
  JSS_PAY_MEMPOOL_URL: 'payMempoolUrl',
  JSS_PAY_ADDRESS: 'payAddress',
  JSS_PAY_TOKEN: 'payToken',
  JSS_PAY_RATE: 'payRate',
  JSS_PAY_CHAINS: 'payChains',
  JSS_MONGO: 'mongo',
  JSS_MONGO_URL: 'mongoUrl',
  JSS_MONGO_DATABASE: 'mongoDatabase',
};

/**
 * Parse a size string like "50MB" or "1GB" to bytes
 */
export function parseSize(str) {
  const match = str.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$/i);
  if (!match) return parseInt(str, 10) || 0;

  const num = parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();
  const multipliers = { B: 1, KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
  return Math.floor(num * (multipliers[unit] || 1));
}

/**
 * Config keys whose values are genuinely boolean. Only these get the
 * "true"/"false" string coercion below — otherwise a user-supplied
 * password (or any other string-valued option) like "true"/"false"
 * would silently turn into a boolean and break downstream code (e.g.
 * bcrypt hashing).
 */
const BOOLEAN_KEYS = new Set([
  'ssl',
  'conneg',
  'subdomains',
  'mashlib',
  'mashlibCdn',
  'git',
  'nostr',
  'webrtc',
  'terminal',
  'tunnel',
  'activitypub',
  'inviteOnly',
  'multiuser',
  'singleUser',
  'webidTls',
  'public',
  'readOnly',
  'liveReload',
  'pay',
  'mongo',
  'idp',
  'notifications',
  'logger',
  'quiet'
]);

/**
 * Parse a value from environment variable string
 */
function parseEnvValue(value, key) {
  if (value === undefined) return undefined;

  // Boolean values — only for known boolean keys; everything else
  // stays a string so passwords / tokens / arbitrary text aren't
  // silently coerced to booleans.
  if (BOOLEAN_KEYS.has(key)) {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }

  // Numeric values for known numeric keys
  if ((key === 'port' || key === 'nostrMaxEvents' || key === 'payCost' || key === 'payRate') && !isNaN(value)) {
    return parseInt(value, 10);
  }

  // Size values (quota)
  if (key === 'defaultQuota') {
    return parseSize(value);
  }

  return value;
}

/**
 * Load configuration from environment variables
 */
function loadEnvConfig() {
  const config = {};

  for (const [envVar, configKey] of Object.entries(envMap)) {
    const value = process.env[envVar];
    if (value !== undefined) {
      config[configKey] = parseEnvValue(value, configKey);
    }
  }

  return config;
}

/**
 * Load configuration from a JSON file
 */
async function loadFileConfig(configFile) {
  if (!configFile) return {};

  try {
    const fullPath = path.resolve(configFile);
    if (await fs.pathExists(fullPath)) {
      const content = await fs.readFile(fullPath, 'utf8');
      return JSON.parse(content);
    }
  } catch (e) {
    console.error(`Warning: Failed to load config file: ${e.message}`);
  }

  return {};
}

/**
 * Merge configuration sources
 * @param {object} cliOptions - Options from command line
 * @param {string} configFile - Path to config file (optional)
 * @returns {Promise<object>} Merged configuration
 */
export async function loadConfig(cliOptions = {}, configFile = null) {
  // Load from file first
  const fileConfig = await loadFileConfig(configFile || cliOptions.config);

  // Load from environment
  const envConfig = loadEnvConfig();

  // Merge in order: defaults < file < env < cli
  const config = {
    ...defaults,
    ...fileConfig,
    ...envConfig,
    ...filterUndefined(cliOptions),
  };

  // Derive additional settings
  if (config.quiet) {
    config.logger = false;
  }

  // Validate log level
  const validLevels = ['fatal', 'error', 'warn', 'info', 'debug', 'trace'];
  if (!validLevels.includes(config.logLevel)) {
    console.warn(`Invalid log level '${config.logLevel}', falling back to 'info'. Valid levels: ${validLevels.join(', ')}`);
    config.logLevel = 'info';
  }

  // Mashlib requires content negotiation for Turtle support
  if (config.mashlib || config.mashlibCdn || config.mashlibModule) {
    config.conneg = true;
  }

  // Single-user mode strongly implies the built-in IdP. Operators seeding
  // a password for `me` on localhost almost always want the IdP enabled
  // so clients can authenticate. Imply --idp unless the user explicitly
  // disabled it via --no-idp (see #331).
  if (config.singleUser && !config.idp) {
    if (cliOptions.idp === false) {
      // User explicitly passed --no-idp. Respect their choice but warn:
      // without the built-in IdP and without an external --idp-issuer,
      // /.well-known/openid-configuration returns 404 and clients fail
      // with confusing OIDC discovery errors.
      console.warn('⚠️  --single-user is enabled but --idp is disabled. Clients won\'t be able to authenticate via the built-in IdP. Use --idp, or pass an external --idp-issuer.');
    } else {
      config.idp = true;
    }
  }

  // Validate SSL config
  if ((config.sslKey && !config.sslCert) || (!config.sslKey && config.sslCert)) {
    throw new Error('Both --ssl-key and --ssl-cert must be provided together');
  }

  config.ssl = !!(config.sslKey && config.sslCert);

  return config;
}

/**
 * Filter out undefined values from an object
 */
function filterUndefined(obj) {
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Save configuration to a file
 */
export async function saveConfig(config, configFile) {
  const toSave = { ...config };
  // Remove derived/runtime values
  delete toSave.ssl;
  delete toSave.logger;
  // Never persist secrets to a static config file. The password is
  // expected to come from --single-user-password or
  // JSS_SINGLE_USER_PASSWORD at runtime, not be written into .jss/config.
  delete toSave.singleUserPassword;

  await fs.ensureDir(path.dirname(configFile));
  await fs.writeFile(configFile, JSON.stringify(toSave, null, 2));
}

/**
 * Print configuration (for debugging)
 */
export function printConfig(config) {
  console.log('\nConfiguration:');
  console.log('─'.repeat(40));
  console.log(`  Port:          ${config.port}`);
  console.log(`  Host:          ${config.host}`);
  console.log(`  Root:          ${path.resolve(config.root)}`);
  console.log(`  SSL:           ${config.ssl ? 'enabled' : 'disabled'}`);
  console.log(`  Multi-user:    ${config.multiuser}`);
  if (config.singleUser) {
    let details = `${config.singleUserName}`;
    // Password seeding only runs when --idp is on AND the pod isn't the
    // root-level case ('/'). Reflect both gates in the printed line so
    // operators don't see a misleading "missing — login disabled" when
    // login isn't governed by an IDP password at all.
    if (config.idp) {
      if (config.singleUserName === '/' || !config.singleUserName) {
        details += ' (root pod; password not seeded)';
      } else {
        const pwSource = config.singleUserPassword
          ? 'provided'
          : (process.stdin.isTTY ? 'will prompt at startup' : 'missing — login disabled');
        details += ` (password: ${pwSource})`;
      }
    }
    console.log(`  Single-user:   ${details}`);
  }
  console.log(`  Conneg:        ${config.conneg}`);
  console.log(`  Notifications: ${config.notifications}`);
  console.log(`  IdP:           ${config.idp ? (config.idpIssuer || 'enabled') : 'disabled'}`);
  console.log(`  Subdomains:    ${config.subdomains ? (config.baseDomain || 'enabled') : 'disabled'}`);
  console.log(`  Mashlib:       ${config.mashlibModule ? `module (${config.mashlibModule})` : config.mashlibCdn ? `CDN v${config.mashlibVersion}` : 'disabled'}`);
  if (config.pay) {
    console.log(`  Pay:           ${config.payCost} sat/req`);
    if (config.payToken) console.log(`  Token:         ${config.payToken} @ ${config.payRate} sat/token`);
  }
  if (config.mongo) console.log(`  MongoDB:       ${config.mongoUrl} (${config.mongoDatabase})`);
  console.log('─'.repeat(40));
}
