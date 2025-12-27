#!/usr/bin/env node

/**
 * JavaScript Solid Server CLI
 *
 * Usage:
 *   jss start [options]    Start the server
 *   jss init               Initialize configuration
 */

import { Command } from 'commander';
import { createServer } from '../src/server.js';
import { loadConfig, saveConfig, printConfig, defaults } from '../src/config.js';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(await fs.readFile(path.join(__dirname, '../package.json'), 'utf8'));

const program = new Command();

program
  .name('jss')
  .description('JavaScript Solid Server - A minimal, fast, JSON-LD native Solid server')
  .version(pkg.version);

/**
 * Start command
 */
program
  .command('start')
  .description('Start the Solid server')
  .option('-p, --port <number>', 'Port to listen on', parseInt)
  .option('-h, --host <address>', 'Host to bind to')
  .option('-r, --root <path>', 'Data directory')
  .option('-c, --config <file>', 'Config file path')
  .option('--ssl-key <path>', 'Path to SSL private key (PEM)')
  .option('--ssl-cert <path>', 'Path to SSL certificate (PEM)')
  .option('--multiuser', 'Enable multi-user mode')
  .option('--no-multiuser', 'Disable multi-user mode')
  .option('--conneg', 'Enable content negotiation (Turtle support)')
  .option('--no-conneg', 'Disable content negotiation')
  .option('--notifications', 'Enable WebSocket notifications')
  .option('--no-notifications', 'Disable WebSocket notifications')
  .option('--idp', 'Enable built-in Identity Provider')
  .option('--no-idp', 'Disable built-in Identity Provider')
  .option('--idp-issuer <url>', 'IdP issuer URL (defaults to server URL)')
  .option('-q, --quiet', 'Suppress log output')
  .option('--print-config', 'Print configuration and exit')
  .action(async (options) => {
    try {
      const config = await loadConfig(options, options.config);

      if (options.printConfig) {
        printConfig(config);
        process.exit(0);
      }

      // Determine IdP issuer URL
      const protocol = config.ssl ? 'https' : 'http';
      const serverHost = config.host === '0.0.0.0' ? 'localhost' : config.host;
      const baseUrl = `${protocol}://${serverHost}:${config.port}`;
      // Ensure issuer has trailing slash for CTH compatibility
      let idpIssuer = config.idpIssuer || baseUrl;
      if (idpIssuer && !idpIssuer.endsWith('/')) {
        idpIssuer = idpIssuer + '/';
      }

      // Create and start server
      const server = createServer({
        logger: config.logger,
        conneg: config.conneg,
        notifications: config.notifications,
        idp: config.idp,
        idpIssuer: idpIssuer,
        ssl: config.ssl ? {
          key: await fs.readFile(config.sslKey),
          cert: await fs.readFile(config.sslCert),
        } : null,
        root: config.root,
      });

      await server.listen({ port: config.port, host: config.host });

      if (!config.quiet) {
        console.log(`\n  JavaScript Solid Server v${pkg.version}`);
        console.log(`  ${baseUrl}/`);
        console.log(`\n  Data: ${path.resolve(config.root)}`);
        if (config.ssl) console.log('  SSL:  enabled');
        if (config.conneg) console.log('  Conneg: enabled');
        if (config.notifications) console.log('  WebSocket: enabled');
        if (config.idp) console.log(`  IdP: ${idpIssuer}`);
        console.log('\n  Press Ctrl+C to stop\n');
      }

      // Handle shutdown
      const shutdown = async () => {
        if (!config.quiet) console.log('\n  Shutting down...');
        await server.close();
        process.exit(0);
      };

      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);

    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

/**
 * Init command - interactive configuration
 */
program
  .command('init')
  .description('Initialize server configuration')
  .option('-c, --config <file>', 'Config file path', './config.json')
  .option('-y, --yes', 'Accept defaults without prompting')
  .action(async (options) => {
    const configFile = path.resolve(options.config);

    // Check if config already exists
    if (await fs.pathExists(configFile)) {
      console.log(`Config file already exists: ${configFile}`);
      const overwrite = options.yes ? true : await confirm('Overwrite?');
      if (!overwrite) {
        console.log('Aborted.');
        process.exit(0);
      }
    }

    let config;

    if (options.yes) {
      // Use defaults
      config = { ...defaults };
    } else {
      // Interactive prompts
      console.log('\n  JavaScript Solid Server Setup\n');

      config = {
        port: await prompt('Port', defaults.port),
        root: await prompt('Data directory', defaults.root),
        conneg: await confirm('Enable content negotiation (Turtle support)?', defaults.conneg),
        notifications: await confirm('Enable WebSocket notifications?', defaults.notifications),
      };

      // Ask about SSL
      const useSSL = await confirm('Configure SSL?', false);
      if (useSSL) {
        config.sslKey = await prompt('SSL key path', './ssl/key.pem');
        config.sslCert = await prompt('SSL certificate path', './ssl/cert.pem');
      }

      // Ask about IdP
      config.idp = await confirm('Enable built-in Identity Provider?', false);
      if (config.idp) {
        const customIssuer = await confirm('Use custom issuer URL?', false);
        if (customIssuer) {
          config.idpIssuer = await prompt('IdP issuer URL', 'https://example.com');
        }
      }

      console.log('');
    }

    // Save config
    await saveConfig(config, configFile);
    console.log(`Configuration saved to: ${configFile}`);

    // Create data directory
    const dataDir = path.resolve(config.root);
    await fs.ensureDir(dataDir);
    console.log(`Data directory created: ${dataDir}`);

    console.log('\nRun `jss start` to start the server.\n');
  });

/**
 * Helper: Prompt for input
 */
async function prompt(question, defaultValue) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    const defaultStr = defaultValue !== undefined ? ` (${defaultValue})` : '';
    rl.question(`  ${question}${defaultStr}: `, (answer) => {
      rl.close();
      const value = answer.trim() || defaultValue;
      // Parse numbers
      if (typeof defaultValue === 'number' && !isNaN(value)) {
        resolve(parseInt(value, 10));
      } else {
        resolve(value);
      }
    });
  });
}

/**
 * Helper: Confirm yes/no
 */
async function confirm(question, defaultValue = false) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    const hint = defaultValue ? '[Y/n]' : '[y/N]';
    rl.question(`  ${question} ${hint}: `, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      if (normalized === '') {
        resolve(defaultValue);
      } else {
        resolve(normalized === 'y' || normalized === 'yes');
      }
    });
  });
}

// Parse and run
program.parse();
