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

  // Logging
  logger: true,
  quiet: false,

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
  JSS_CONFIG_PATH: 'configPath',
  JSS_IDP: 'idp',
  JSS_IDP_ISSUER: 'idpIssuer',
  JSS_SUBDOMAINS: 'subdomains',
  JSS_BASE_DOMAIN: 'baseDomain',
};

/**
 * Parse a value from environment variable string
 */
function parseEnvValue(value, key) {
  if (value === undefined) return undefined;

  // Boolean values
  if (value.toLowerCase() === 'true') return true;
  if (value.toLowerCase() === 'false') return false;

  // Numeric values for known numeric keys
  if (key === 'port' && !isNaN(value)) {
    return parseInt(value, 10);
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
  console.log('─'.repeat(40));
}
