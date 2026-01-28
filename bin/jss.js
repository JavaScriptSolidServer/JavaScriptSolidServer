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
import { createInvite, listInvites, revokeInvite } from '../src/idp/invites.js';
import { setQuotaLimit, getQuotaInfo, reconcileQuota, formatBytes } from '../src/storage/quota.js';
import { parseSize } from '../src/config.js';
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
  .option('--subdomains', 'Enable subdomain-based pods (XSS protection)')
  .option('--no-subdomains', 'Disable subdomain-based pods')
  .option('--base-domain <domain>', 'Base domain for subdomain pods (e.g., "example.com")')
  .option('--mashlib', 'Enable Mashlib data browser (local mode, requires mashlib in node_modules)')
  .option('--mashlib-cdn', 'Enable Mashlib data browser (CDN mode, no local files needed)')
  .option('--no-mashlib', 'Disable Mashlib data browser')
  .option('--mashlib-version <version>', 'Mashlib version for CDN mode (default: 2.0.0)')
  .option('--solidos-ui', 'Enable modern Nextcloud-style UI (requires --mashlib)')
  .option('--git', 'Enable Git HTTP backend (clone/push support)')
  .option('--no-git', 'Disable Git HTTP backend')
  .option('--nostr', 'Enable Nostr relay')
  .option('--no-nostr', 'Disable Nostr relay')
  .option('--nostr-path <path>', 'Nostr relay WebSocket path (default: /relay)')
  .option('--nostr-max-events <n>', 'Max events in relay memory (default: 1000)', parseInt)
  .option('--activitypub', 'Enable ActivityPub federation')
  .option('--no-activitypub', 'Disable ActivityPub federation')
  .option('--ap-username <name>', 'ActivityPub username (default: me)')
  .option('--ap-display-name <name>', 'ActivityPub display name')
  .option('--ap-summary <text>', 'ActivityPub bio/summary')
  .option('--ap-nostr-pubkey <hex>', 'Nostr pubkey for identity linking')
  .option('--invite-only', 'Require invite code for registration')
  .option('--no-invite-only', 'Allow open registration')
  .option('--single-user', 'Single-user mode (creates pod on startup, disables registration)')
  .option('--single-user-name <name>', 'Username for single-user mode (default: me)')
  .option('--webid-tls', 'Enable WebID-TLS client certificate authentication')
  .option('--no-webid-tls', 'Disable WebID-TLS authentication')
  .option('--public', 'Allow unauthenticated access (skip WAC, open read/write)')
  .option('--read-only', 'Disable PUT/DELETE/PATCH methods (read-only mode)')
  .option('--live-reload', 'Inject live reload script into HTML (auto-refresh on changes)')
  .option('-q, --quiet', 'Suppress log output')
  .option('--print-config', 'Print configuration and exit')
  .action(async (options) => {
    try {
      const config = await loadConfig(options, options.config);

      // Set DATA_ROOT env var so all modules use the same data directory
      process.env.DATA_ROOT = path.resolve(config.root);

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
        port: config.port,
        host: config.host,
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
        subdomains: config.subdomains,
        baseDomain: config.baseDomain,
        mashlib: config.mashlib || config.mashlibCdn,
        mashlibCdn: config.mashlibCdn,
        mashlibVersion: config.mashlibVersion,
        solidosUi: config.solidosUi,
        git: config.git,
        nostr: config.nostr,
        nostrPath: config.nostrPath,
        nostrMaxEvents: config.nostrMaxEvents,
        activitypub: config.activitypub,
        apUsername: config.apUsername,
        apDisplayName: config.apDisplayName,
        apSummary: config.apSummary,
        apNostrPubkey: config.apNostrPubkey,
        inviteOnly: config.inviteOnly,
        webidTls: config.webidTls,
        singleUser: config.singleUser,
        singleUserName: config.singleUserName,
        public: config.public,
        readOnly: config.readOnly,
        liveReload: config.liveReload,
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
        if (config.subdomains) console.log(`  Subdomains: ${config.baseDomain} (XSS protection enabled)`);
        if (config.mashlibCdn) {
          console.log(`  Mashlib: v${config.mashlibVersion} (CDN mode)`);
        } else if (config.mashlib) {
          console.log(`  Mashlib: local (data browser enabled)`);
        }
        if (config.solidosUi) console.log('  SolidOS UI: enabled (modern interface)');
        if (config.git) console.log('  Git: enabled (clone/push support)');
        if (config.nostr) console.log(`  Nostr: enabled (${config.nostrPath})`);
        if (config.activitypub) console.log(`  ActivityPub: enabled (@${config.apUsername || 'me'})`);
        if (config.singleUser) console.log(`  Single-user: ${config.singleUserName || 'me'} (registration disabled)`);
        else if (config.inviteOnly) console.log('  Registration: invite-only');
        if (config.webidTls) console.log('  WebID-TLS: enabled (client certificate auth)');
        if (config.public) {
          console.log('');
          console.log('  ⚠️  WARNING: PUBLIC MODE ENABLED');
          console.log('     All files are accessible without authentication.');
          if (!config.readOnly) {
            console.log('     Anyone can read, write, and delete files.');
          }
          console.log('     Do not expose to the internet!');
        }
        if (config.readOnly) console.log('  Read-only: enabled (PUT/DELETE/PATCH disabled)');
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
 * Invite command - manage invite codes
 */
const inviteCmd = program
  .command('invite')
  .description('Manage invite codes for registration');

inviteCmd
  .command('create')
  .description('Create a new invite code')
  .option('-u, --uses <number>', 'Maximum uses (default: 1)', parseInt, 1)
  .option('-n, --note <text>', 'Optional note/description')
  .option('-r, --root <path>', 'Data directory')
  .action(async (options) => {
    try {
      // Set DATA_ROOT if provided
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const { code, invite } = await createInvite({
        maxUses: options.uses,
        note: options.note || ''
      });

      console.log(`\nCreated invite code: ${code}`);
      if (invite.maxUses > 1) {
        console.log(`Uses: 0/${invite.maxUses}`);
      }
      if (invite.note) {
        console.log(`Note: ${invite.note}`);
      }
      console.log('');
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

inviteCmd
  .command('list')
  .description('List all invite codes')
  .option('-r, --root <path>', 'Data directory')
  .action(async (options) => {
    try {
      // Set DATA_ROOT if provided
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const invites = await listInvites();

      if (invites.length === 0) {
        console.log('\nNo invite codes found.\n');
        return;
      }

      console.log('\n  CODE        USES     CREATED      NOTE');
      console.log('  ' + '-'.repeat(55));

      for (const invite of invites) {
        const uses = `${invite.uses}/${invite.maxUses}`.padEnd(8);
        const created = invite.created.split('T')[0];
        const note = invite.note || '';
        console.log(`  ${invite.code}    ${uses} ${created}   ${note}`);
      }
      console.log('');
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

inviteCmd
  .command('revoke <code>')
  .description('Revoke an invite code')
  .option('-r, --root <path>', 'Data directory')
  .action(async (code, options) => {
    try {
      // Set DATA_ROOT if provided
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const success = await revokeInvite(code);

      if (success) {
        console.log(`\nRevoked invite code: ${code.toUpperCase()}\n`);
      } else {
        console.log(`\nInvite code not found: ${code.toUpperCase()}\n`);
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

/**
 * Quota command - manage storage quotas
 */
const quotaCmd = program
  .command('quota')
  .description('Manage storage quotas for pods');

quotaCmd
  .command('set <username> <size>')
  .description('Set quota limit for a user (e.g., 50MB, 1GB)')
  .option('-r, --root <path>', 'Data directory')
  .action(async (username, size, options) => {
    try {
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const bytes = parseSize(size);
      if (bytes === 0) {
        console.error('Invalid size format. Use e.g., 50MB, 1GB');
        process.exit(1);
      }

      const quota = await setQuotaLimit(username, bytes);
      console.log(`\nQuota set for ${username}: ${formatBytes(quota.limit)}`);
      console.log(`Current usage: ${formatBytes(quota.used)} (${Math.round(quota.used / quota.limit * 100)}%)\n`);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

quotaCmd
  .command('show <username>')
  .description('Show quota info for a user')
  .option('-r, --root <path>', 'Data directory')
  .action(async (username, options) => {
    try {
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const quota = await getQuotaInfo(username);

      if (quota.limit === 0) {
        console.log(`\n${username}: No quota set (unlimited)\n`);
      } else {
        console.log(`\n${username}:`);
        console.log(`  Used:  ${formatBytes(quota.used)}`);
        console.log(`  Limit: ${formatBytes(quota.limit)}`);
        console.log(`  Free:  ${formatBytes(quota.limit - quota.used)}`);
        console.log(`  Usage: ${quota.percent}%\n`);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

quotaCmd
  .command('reconcile <username>')
  .description('Recalculate quota usage from actual disk usage')
  .option('-r, --root <path>', 'Data directory')
  .action(async (username, options) => {
    try {
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      console.log(`Calculating actual disk usage for ${username}...`);
      const quota = await reconcileQuota(username);

      if (quota.limit === 0) {
        console.log(`\n${username}: No quota configured\n`);
      } else {
        console.log(`\nReconciled ${username}:`);
        console.log(`  Used:  ${formatBytes(quota.used)}`);
        console.log(`  Limit: ${formatBytes(quota.limit)}`);
        console.log(`  Usage: ${Math.round(quota.used / quota.limit * 100)}%\n`);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
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
