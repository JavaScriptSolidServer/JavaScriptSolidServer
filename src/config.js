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
  port: 3000,
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

  // SolidOS UI (modern Nextcloud-style interface)
  solidosUi: false,

  // Git HTTP backend
  git: false,

  // Nostr relay
  nostr: false,
  nostrPath: '/relay',
  nostrMaxEvents: 1000,

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
  JSS_SOLIDOS_UI: 'solidosUi',
  JSS_GIT: 'git',
  JSS_NOSTR: 'nostr',
  JSS_NOSTR_PATH: 'nostrPath',
  JSS_NOSTR_MAX_EVENTS: 'nostrMaxEvents',
  JSS_ACTIVITYPUB: 'activitypub',
  JSS_AP_USERNAME: 'apUsername',
  JSS_AP_DISPLAY_NAME: 'apDisplayName',
  JSS_AP_SUMMARY: 'apSummary',
  JSS_AP_NOSTR_PUBKEY: 'apNostrPubkey',
  JSS_INVITE_ONLY: 'inviteOnly',
  JSS_SINGLE_USER: 'singleUser',
  JSS_SINGLE_USER_NAME: 'singleUserName',
  JSS_WEBID_TLS: 'webidTls',
  JSS_DEFAULT_QUOTA: 'defaultQuota',
  JSS_PUBLIC: 'public',
  JSS_READ_ONLY: 'readOnly',
  JSS_LIVE_RELOAD: 'liveReload',
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
 * Parse a value from environment variable string
 */
function parseEnvValue(value, key) {
  if (value === undefined) return undefined;

  // Boolean values
  if (value.toLowerCase() === 'true') return true;
  if (value.toLowerCase() === 'false') return false;

  // Numeric values for known numeric keys
  if ((key === 'port' || key === 'nostrMaxEvents') && !isNaN(value)) {
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
  console.log(`  Conneg:        ${config.conneg}`);
  console.log(`  Notifications: ${config.notifications}`);
  console.log(`  IdP:           ${config.idp ? (config.idpIssuer || 'enabled') : 'disabled'}`);
  console.log(`  Subdomains:    ${config.subdomains ? (config.baseDomain || 'enabled') : 'disabled'}`);
  console.log(`  Mashlib:       ${config.mashlibModule ? `module (${config.mashlibModule})` : config.mashlibCdn ? `CDN v${config.mashlibVersion}` : config.mashlib ? 'local' : 'disabled'}`);
  console.log(`  SolidOS UI:    ${config.solidosUi ? 'enabled' : 'disabled'}`);
  console.log('─'.repeat(40));
}
