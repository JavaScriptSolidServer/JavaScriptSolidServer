#!/usr/bin/env node

/**
 * JavaScript Solid Server CLI
 *
 * Usage:
 *   jss start [options]    Start the server
 *   jss init               Initialize configuration
 *   jss passwd <username>  Change user password
 */

import { Command } from 'commander';
import { createServer } from '../src/server.js';
import { loadConfig, saveConfig, printConfig, defaults } from '../src/config.js';
import { createInvite, listInvites, revokeInvite } from '../src/idp/invites.js';
import { findByUsername, updatePassword, deleteAccount } from '../src/idp/accounts.js';
import { setQuotaLimit, getQuotaInfo, reconcileQuota, formatBytes } from '../src/storage/quota.js';
import { parseSize } from '../src/config.js';
import crypto from 'crypto';
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
 * Convert a camelCase option name back to its kebab-case CLI form for
 * error messages (`singleUserName` → `single-user-name`).
 */
function camelToKebab (name) {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
}

/**
 * Reject any option value that looks like another flag (#103).
 *
 * Commander happily consumes the next argv as a value, so
 *   `jss start --single-user-name --idp`
 * silently sets `singleUserName="--idp"` and the IdP flag is lost.
 * This validator runs as a `preAction` hook for every subcommand, so
 * any option with a missing value gets a clear error instead of a
 * confusing downstream failure ("issuer has no registration endpoint",
 * "Single-user: --idp" in the banner, etc.).
 */
program.hook('preAction', (_thisCommand, actionCommand) => {
  const opts = actionCommand.opts();
  for (const [key, value] of Object.entries(opts)) {
    const flag = camelToKebab(key);
    if (typeof value === 'string' && value.startsWith('--')) {
      console.error(
        `Error: --${flag} value "${value}" looks like a flag, not a value.\n` +
        `Hint: did you forget to provide a value? e.g. --${flag} someValue`
      );
      process.exit(1);
    }
    // Numeric options (parseInt-coerced like --port) silently produce
    // NaN when given a flag like `--idp`. Catch that too — same root
    // cause, different surface.
    if (typeof value === 'number' && Number.isNaN(value)) {
      console.error(
        `Error: --${flag} got a non-numeric value (parsed as NaN).\n` +
        `Hint: did you forget to provide a number? e.g. --${flag} 8080`
      );
      process.exit(1);
    }
  }
});

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
  .option('--provision-keys', 'Generate a Schnorr secp256k1 owner key on pod creation, written to <pod>/private/privkey.jsonld in W3C CID v1.0 Multikey format (off by default)')
  .option('--no-provision-keys', 'Do not auto-generate an owner key on pod creation')
  .option('--idp-issuer <url>', 'IdP issuer URL (defaults to server URL)')
  .option('--subdomains', 'Enable subdomain-based pods (XSS protection)')
  .option('--no-subdomains', 'Disable subdomain-based pods')
  .option('--base-domain <domain>', 'Base domain for subdomain pods (e.g., "example.com")')
  .option('--mashlib-cdn', 'Enable Mashlib data browser (CDN mode)')
  .option('--mashlib-module <url>', 'Enable ES module data browser from a URL')
  .option('--no-mashlib', 'Disable Mashlib data browser')
  .option('--mashlib-version <version>', 'Mashlib version for CDN mode (default: 2.0.0)')
  .option('--git', 'Enable Git HTTP backend (clone/push support)')
  .option('--no-git', 'Disable Git HTTP backend')
  .option('--cors-proxy', 'Enable CORS proxy at /proxy?url=... for browser apps (WAC-gated)')
  .option('--no-cors-proxy', 'Disable CORS proxy')
  .option('--cors-proxy-max-bytes <n>', 'CORS proxy upstream response size cap (default 50MB)', parseInt)
  .option('--cors-proxy-timeout-ms <ms>', 'CORS proxy upstream request timeout (default 30s)', parseInt)
  .option('--cors-proxy-max-redirects <n>', 'CORS proxy max redirect hops, each re-validated (default 5)', parseInt)
  .option('--nostr', 'Enable Nostr relay')
  .option('--no-nostr', 'Disable Nostr relay')
  .option('--nostr-path <path>', 'Nostr relay WebSocket path (default: /relay)')
  .option('--nostr-max-events <n>', 'Max events in relay memory (default: 1000)', parseInt)
  .option('--webrtc', 'Enable WebRTC signaling server')
  .option('--no-webrtc', 'Disable WebRTC signaling server')
  .option('--webrtc-path <path>', 'WebRTC signaling WebSocket path (default: /.webrtc)')
  .option('--terminal', 'Enable WebSocket terminal (shell access)')
  .option('--no-terminal', 'Disable WebSocket terminal')
  .option('--tunnel', 'Enable tunnel proxy (decentralized ngrok)')
  .option('--no-tunnel', 'Disable tunnel proxy')
  .option('--tunnel-path <path>', 'Tunnel WebSocket path (default: /.tunnel)')
  .option('--activitypub', 'Enable ActivityPub federation')
  .option('--no-activitypub', 'Disable ActivityPub federation')
  .option('--ap-username <name>', 'ActivityPub username (default: me)')
  .option('--ap-display-name <name>', 'ActivityPub display name')
  .option('--ap-summary <text>', 'ActivityPub bio/summary')
  .option('--ap-nostr-pubkey <hex>', 'Nostr pubkey for identity linking')
  .option('--invite-only', 'Require invite code for registration')
  .option('--no-invite-only', 'Allow open registration')
  .option('--single-user', 'Single-user mode (creates pod on startup, disables registration)')
  .option('--single-user-name <name>', 'Mount the pod at /<name>/ instead of at the server root (default: root pod at /)')
  .option('--single-user-password <pw>', 'Initial IDP password to seed when creating the single-user pod (or set JSS_SINGLE_USER_PASSWORD)')
  .option('--webid-tls', 'Enable WebID-TLS client certificate authentication')
  .option('--no-webid-tls', 'Disable WebID-TLS authentication')
  .option('--public', 'Allow unauthenticated access (skip WAC, open read/write)')
  .option('--read-only', 'Disable PUT/DELETE/PATCH methods (read-only mode)')
  .option('--live-reload', 'Inject live reload script into HTML (auto-refresh on changes)')
  .option('--pay', 'Enable HTTP 402 paid access for /pay/* routes')
  .option('--no-pay', 'Disable HTTP 402 paid access')
  .option('--pay-cost <n>', 'Cost per request in satoshis (default: 1)', parseInt)
  .option('--pay-mempool-url <url>', 'Mempool API URL for deposit verification')
  .option('--pay-address <addr>', 'Address for receiving deposits')
  .option('--pay-token <ticker>', 'Token to sell (enables primary market)')
  .option('--pay-rate <n>', 'Sats per token for primary market (default: 1)', parseInt)
  .option('--pay-chains <chains>', 'Comma-separated chain IDs for multi-chain deposits/AMM (e.g. "tbtc3,tbtc4")')
  .option('--mongo', 'Enable MongoDB-backed /db/ route')
  .option('--no-mongo', 'Disable MongoDB-backed /db/ route')
  .option('--mongo-url <url>', 'MongoDB connection URL (default: mongodb://localhost:27017)')
  .option('--mongo-database <name>', 'MongoDB database name (default: solid)')
  .option('-q, --quiet', 'Suppress log output')
  .option('--log-level <level>', 'Log level: error, warn, info, debug (default: info)')
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
        mashlibModule: config.mashlibModule,
        git: config.git,
        corsProxy: config.corsProxy,
        corsProxyMaxBytes: config.corsProxyMaxBytes,
        corsProxyTimeoutMs: config.corsProxyTimeoutMs,
        corsProxyMaxRedirects: config.corsProxyMaxRedirects,
        nostr: config.nostr,
        nostrPath: config.nostrPath,
        nostrMaxEvents: config.nostrMaxEvents,
        webrtc: config.webrtc,
        webrtcPath: config.webrtcPath,
        terminal: config.terminal,
        tunnel: config.tunnel,
        tunnelPath: config.tunnelPath,
        activitypub: config.activitypub,
        apUsername: config.apUsername,
        apDisplayName: config.apDisplayName,
        apSummary: config.apSummary,
        apNostrPubkey: config.apNostrPubkey,
        inviteOnly: config.inviteOnly,
        webidTls: config.webidTls,
        singleUser: config.singleUser,
        singleUserName: config.singleUserName,
        singleUserPassword: config.singleUserPassword,
        provisionKeys: config.provisionKeys,
        public: config.public,
        readOnly: config.readOnly,
        liveReload: config.liveReload,
        pay: config.pay,
        payCost: config.payCost,
        payMempoolUrl: config.payMempoolUrl,
        payAddress: config.payAddress,
        payToken: config.payToken,
        payRate: config.payRate,
        payChains: config.payChains,
        mongo: config.mongo,
        mongoUrl: config.mongoUrl,
        mongoDatabase: config.mongoDatabase,
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
        if (config.mashlibModule) console.log(`  Mashlib module: ${config.mashlibModule}`);
        if (config.git) console.log('  Git: enabled (clone/push support)');
        if (config.corsProxy) console.log('  CORS proxy: enabled (/proxy?url=..., WAC-gated)');
        if (config.nostr) console.log(`  Nostr: enabled (${config.nostrPath})`);
        if (config.webrtc) console.log(`  WebRTC: enabled (${config.webrtcPath || '/.webrtc'})`);
        if (config.terminal) console.log('  Terminal: enabled (/.terminal)');
        if (config.tunnel) console.log(`  Tunnel: enabled (${config.tunnelPath || '/.tunnel'})`);
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
        if (config.pay) {
          console.log(`  Pay: ${config.payCost} sat/req (402 enabled)`);
          if (config.payToken) console.log(`  Token: ${config.payToken} @ ${config.payRate} sat/token`);
        }
        if (config.mongo) console.log(`  MongoDB: ${config.mongoUrl} (${config.mongoDatabase})`);
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

      // Gracefully handle ECONNRESET — normal network noise from clients
      // closing connections early (browser navigation, health checks, etc.)
      process.on('uncaughtException', (err) => {
        if (err.code === 'ECONNRESET' || err.code === 'EPIPE' || err.code === 'ECONNABORTED') {
          return;
        }
        console.error('Uncaught exception:', err);
        process.exit(1);
      });

    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

/**
 * Install command — install a Solid app from the default registry
 * (`github.com/solid-apps/<name>`) into a running pod.
 *
 * Phase 1 of #464 / scoped in #478. Hardcodes the default registry;
 * later phases add <org>/<repo>, full URLs, refs, renames, did:nostr
 * resolution, NIP-98 auth, curated default sets, and --bundle.
 */
program
  .command('install [names...]')
  .description('Install a Solid app (or a bundle of apps) into a running pod')
  .option('--pod <url>', 'Target pod URL', 'http://localhost:4443')
  .option('--user <name>', 'Username for IDP auth', 'me')
  .option('--password <pw>', 'Password (default: $JSS_SINGLE_USER_PASSWORD or "me")')
  .option('--nostr-privkey <hex>', 'Sign install pushes with NIP-98 using this 64-char hex Nostr privkey instead of fetching a bearer token (default: $NOSTR_PRIVKEY)')
  .option('--bundle <source>', 'Install everything in a bundle (JSON-LD doc). Source: bare name → solid-apps/bundles, <org>/<repo>, https://..., or a local path')
  .action(async (names, options) => {
    try {
      const { runInstall } = await import('../src/cli/install.js');
      await runInstall(names, options);
    } catch (err) {
      // runInstall prints its own per-app error lines; we just exit non-zero.
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
  .option('-u, --uses <number>', 'Maximum uses (default: 1)', (v) => parseInt(v, 10), 1)
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
 * Token command - manage MRC20 tokens
 */
const tokenCmd = program
  .command('token')
  .description('Manage MRC20 tokens anchored to Bitcoin');

tokenCmd
  .command('mint')
  .description('Create a new MRC20 token')
  .requiredOption('-t, --ticker <ticker>', 'Token ticker symbol')
  .requiredOption('-s, --supply <n>', 'Total supply', parseInt)
  .requiredOption('-v, --voucher <txo>', 'Funded TXO URI (txo:btc:txid:vout?amount=N&key=hex)')
  .option('-n, --name <name>', 'Token name (defaults to ticker)')
  .option('-r, --root <path>', 'Data directory')
  .option('--mempool-url <url>', 'Mempool API URL', 'https://mempool.space/testnet4')
  .option('--network <net>', 'Bitcoin network (testnet4 or mainnet)', 'testnet4')
  .action(async (options) => {
    try {
      if (options.root) process.env.DATA_ROOT = path.resolve(options.root);
      const { mintToken } = await import('../src/token.js');
      console.log(`\nMinting ${options.supply} ${options.ticker}...`);
      const result = await mintToken({
        ticker: options.ticker,
        name: options.name,
        supply: options.supply,
        voucher: options.voucher,
        mempoolUrl: options.mempoolUrl,
        network: options.network
      });
      console.log(`\nToken minted!`);
      console.log(`  Ticker:  ${options.ticker}`);
      console.log(`  Supply:  ${options.supply}`);
      console.log(`  Issuer:  ${result.trail.pubkeyBase}`);
      console.log(`  TX:      ${result.txid}`);
      console.log(`  Address: ${result.address}`);
      console.log('');
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

tokenCmd
  .command('transfer')
  .description('Transfer tokens to an address')
  .requiredOption('-t, --ticker <ticker>', 'Token ticker symbol')
  .requiredOption('--to <address>', 'Recipient address (pubkey hex)')
  .requiredOption('-a, --amount <n>', 'Amount to transfer', parseInt)
  .option('-r, --root <path>', 'Data directory')
  .option('--mempool-url <url>', 'Mempool API URL', 'https://mempool.space/testnet4')
  .action(async (options) => {
    try {
      if (options.root) process.env.DATA_ROOT = path.resolve(options.root);
      const { transferToken } = await import('../src/token.js');
      console.log(`\nTransferring ${options.amount} ${options.ticker} to ${options.to.slice(0, 16)}...`);
      const result = await transferToken({
        ticker: options.ticker,
        to: options.to,
        amount: options.amount,
        mempoolUrl: options.mempoolUrl
      });
      console.log(`\nTransfer complete!`);
      console.log(`  TX:      ${result.txid}`);
      console.log(`  Address: ${result.address}`);
      console.log(`  Balance: ${JSON.stringify(result.trail.states[result.trail.states.length - 1].balances)}`);
      console.log('');
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

tokenCmd
  .command('info [ticker]')
  .description('Show token info (or list all tokens)')
  .option('-r, --root <path>', 'Data directory')
  .action(async (ticker, options) => {
    try {
      if (options.root) process.env.DATA_ROOT = path.resolve(options.root);
      const { tokenInfo, listTrails } = await import('../src/token.js');

      if (!ticker) {
        // List all tokens
        const trails = await listTrails();
        if (trails.length === 0) {
          console.log('\nNo tokens found.\n');
          return;
        }
        console.log('\n  TICKER   SUPPLY   SEQ   SATS       CREATED');
        console.log('  ' + '-'.repeat(55));
        for (const t of trails) {
          const state = t.states[t.states.length - 1];
          console.log(`  ${t.ticker.padEnd(8)} ${String(t.supply).padEnd(8)} ${String(state.seq).padEnd(5)} ${String(t.currentAmount).padEnd(10)} ${t.dateCreated.split('T')[0]}`);
        }
        console.log('');
        return;
      }

      const info = await tokenInfo(ticker);
      console.log(`\n  ${info.ticker} — ${info.name}`);
      console.log('  ' + '-'.repeat(40));
      console.log(`  Supply:    ${info.supply}`);
      console.log(`  Seq:       ${info.seq}`);
      console.log(`  Issuer:    ${info.pubkeyBase}`);
      console.log(`  Network:   ${info.network}`);
      console.log(`  TX:        ${info.currentTxid}`);
      console.log(`  Address:   ${info.currentAddress}`);
      console.log(`  UTXO sats: ${info.currentAmount}`);
      console.log(`  Created:   ${info.dateCreated}`);
      console.log('  Balances:');
      for (const [addr, bal] of Object.entries(info.balances)) {
        const label = addr === info.pubkeyBase ? `${addr.slice(0, 16)}... (issuer)` : `${addr.slice(0, 16)}...`;
        console.log(`    ${label}: ${bal}`);
      }
      console.log('');
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

/**
 * Passwd command - change a user's password
 */
program
  .command('passwd <username>')
  .description('Change password for a user account')
  .option('-p, --password <password>', 'New password (non-interactive)')
  .option('-g, --generate', 'Generate a random password')
  .option('-r, --root <path>', 'Data directory')
  .action(async (username, options) => {
    try {
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const account = await findByUsername(username);
      if (!account) {
        console.error(`Error: User not found: ${username}`);
        process.exit(1);
      }

      // Determine new password
      let newPassword;

      if (options.generate) {
        newPassword = crypto.randomBytes(16).toString('base64url');
      } else if (options.password) {
        newPassword = options.password;
      } else {
        // Interactive prompt
        newPassword = await promptPassword('New password: ');
        const confirmation = await promptPassword('Confirm password: ');
        if (newPassword !== confirmation) {
          console.error('Error: Passwords do not match');
          process.exit(1);
        }
      }

      if (!newPassword) {
        console.error('Error: Password cannot be empty');
        process.exit(1);
      }

      await updatePassword(account.id, newPassword);

      if (options.generate) {
        console.log(`\nPassword updated for ${account.username}`);
        console.log(`Generated password: ${newPassword}\n`);
      } else {
        console.log(`\nPassword updated for ${account.username}\n`);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

/**
 * Account commands - manage user accounts
 */
const accountCmd = program
  .command('account')
  .description('Manage user accounts');

accountCmd
  .command('delete <username>')
  .description('Delete a user account from the IdP')
  .option('-r, --root <path>',  'Data directory')
  .option('-y, --yes',          'Skip the confirmation prompt')
  .option('--purge',            'Also delete pod data at <dataRoot>/<username>/')
  .action(async (username, options) => {
    try {
      if (options.root) {
        process.env.DATA_ROOT = path.resolve(options.root);
      }

      const account = await findByUsername(username);
      if (!account) {
        console.error(`Error: User not found: ${username}`);
        process.exit(1);
      }

      if (!options.yes) {
        const summary = `Delete account '${account.username}' (${account.webId})${options.purge ? ' AND purge pod data' : ''}?`;
        const ok = await confirm(summary, false);
        if (!ok) {
          console.log('Cancelled.');
          process.exit(0);
        }
      }

      await deleteAccount(account.id);

      if (options.purge) {
        const dataRoot = process.env.DATA_ROOT || './data';
        // Use podName, not username — createAccount lowercases the
        // username but pod directories on disk preserve the original
        // case. On case-sensitive filesystems they can differ.
        const podPath = path.join(dataRoot, account.podName || account.username);
        await fs.remove(podPath);
        console.log(`\nDeleted account ${account.username}. Pod data removed from ${podPath}.\n`);
      } else {
        const podDir = account.podName || account.username;
        console.log(`\nDeleted account ${account.username}. Pod data preserved at <dataRoot>/${podDir}/ (use --purge to remove).\n`);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

/**
 * Helper: Prompt for a password (hidden input)
 */
async function promptPassword(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    // Disable echo for password input
    if (process.stdin.isTTY) {
      process.stdout.write(`  ${question}`);
      const stdin = process.openStdin();
      process.stdin.setRawMode(true);
      let password = '';
      const onData = (ch) => {
        const c = ch.toString('utf8');
        if (c === '\n' || c === '\r' || c === '\u0004') {
          process.stdin.setRawMode(false);
          process.stdin.removeListener('data', onData);
          process.stdout.write('\n');
          rl.close();
          resolve(password);
        } else if (c === '\u0003') {
          // Ctrl+C
          process.exit(0);
        } else if (c === '\u007f' || c === '\b') {
          // Backspace
          if (password.length > 0) {
            password = password.slice(0, -1);
          }
        } else {
          password += c;
        }
      };
      process.stdin.on('data', onData);
    } else {
      // Non-TTY: read line normally (piped input)
      rl.question(`  ${question}`, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    }
  });
}

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
