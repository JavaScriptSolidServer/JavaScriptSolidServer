/**
 * Clock Updater - Updates the Solid clock every second using Nostr auth
 * Usage: node clock-updater.mjs
 */

import { getPublicKey, nip98Token } from './test/helpers/nostr-event.js';

// Nostr keypair (in production, load from env/file)
const SK_HEX = '3f188544fb81bd324ead7be9697fd9503d18345e233a7b0182915b0b582ddd70';
const sk = Uint8Array.from(Buffer.from(SK_HEX, 'hex'));
const pk = getPublicKey(sk);

const CLOCK_URL = 'https://solid.social/melvin/public/clock.json';

async function updateClock() {
  const now = Math.floor(Date.now() / 1000);
  const isoDate = new Date(now * 1000).toISOString();

  const clockData = {
    '@context': { 'schema': 'http://schema.org/' },
    '@id': '#clock',
    '@type': 'schema:Clock',
    'schema:dateModified': isoDate,
    'schema:value': now
  };

  try {
    const token = nip98Token(CLOCK_URL, 'PUT', sk, clockData);

    const res = await fetch(CLOCK_URL, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/ld+json',
        'Authorization': 'Nostr ' + token
      },
      body: JSON.stringify(clockData)
    });

    const time = isoDate.split('T')[1].replace('Z', '');
    if (res.ok) {
      process.stdout.write(`\r${time} - Updated`);
    } else {
      console.log(`\n${time} - Error: ${res.status} ${res.statusText}`);
    }
  } catch (err) {
    console.log(`\nError: ${err.message}`);
  }
}

console.log('Clock Updater started');
console.log('did:nostr:', 'did:nostr:' + pk);
console.log('Target:', CLOCK_URL);
console.log('Press Ctrl+C to stop\n');

// Run immediately, then every second
updateClock();
setInterval(updateClock, 1000);
