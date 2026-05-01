/**
 * Clock Updater - Updates the Solid clock every second using Nostr auth
 * Usage: node clock-updater.mjs
 */

import { getPublicKey, nip98Token } from './src/nostr/event.js';

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
    // Serialize once: the same bytes feed both the NIP-98 payload hash
    // and the fetch body. nip98Token requires bytes (not an object) so
    // the `payload` tag matches what the server actually receives.
    const bodyBytes = JSON.stringify(clockData);
    const token = nip98Token(CLOCK_URL, 'PUT', sk, bodyBytes);

    const res = await fetch(CLOCK_URL, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/ld+json',
        'Authorization': 'Nostr ' + token
      },
      body: bodyBytes
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
