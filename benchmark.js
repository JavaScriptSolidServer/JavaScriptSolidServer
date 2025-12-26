#!/usr/bin/env node
/**
 * Benchmark script for JavaScript Solid Server
 *
 * Measures throughput and latency for common operations.
 * Run: node benchmark.js
 */

import autocannon from 'autocannon';
import { createServer } from './src/server.js';
import fs from 'fs-extra';

const PORT = 3030;
const DURATION = 10; // seconds per test
const CONNECTIONS = 10;

let server;
let token;

async function setup() {
  // Clean data directory
  await fs.emptyDir('./data');

  // Start server (no logging for clean benchmark)
  server = createServer({ logger: false });
  await server.listen({ port: PORT, host: '127.0.0.1' });

  // Create a test pod
  const res = await fetch(`http://127.0.0.1:${PORT}/.pods`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'bench' })
  });
  const data = await res.json();
  token = data.token;

  // Create some test resources
  for (let i = 0; i < 100; i++) {
    await fetch(`http://127.0.0.1:${PORT}/bench/public/item${i}.json`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/ld+json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ '@id': `#item${i}`, 'http://example.org/value': i })
    });
  }

  console.log('Setup complete: created pod with 100 resources\n');
}

async function teardown() {
  await server.close();
  await fs.emptyDir('./data');
}

function runBenchmark(opts) {
  return new Promise((resolve) => {
    const instance = autocannon({
      ...opts,
      duration: DURATION,
      connections: CONNECTIONS,
    }, (err, result) => {
      resolve(result);
    });

    autocannon.track(instance, { renderProgressBar: false });
  });
}

function formatResult(result) {
  return {
    'Requests/sec': Math.round(result.requests.average),
    'Latency avg': `${result.latency.average.toFixed(2)}ms`,
    'Latency p99': `${result.latency.p99.toFixed(2)}ms`,
    'Throughput': `${(result.throughput.average / 1024 / 1024).toFixed(2)} MB/s`
  };
}

async function benchmarkGET() {
  console.log('📖 Benchmarking GET (read resource)...');
  const result = await runBenchmark({
    url: `http://127.0.0.1:${PORT}/bench/public/item0.json`,
    method: 'GET'
  });
  return formatResult(result);
}

async function benchmarkGETContainer() {
  console.log('📂 Benchmarking GET (container listing)...');
  const result = await runBenchmark({
    url: `http://127.0.0.1:${PORT}/bench/public/`,
    method: 'GET'
  });
  return formatResult(result);
}

let putCounter = 1000;
async function benchmarkPUT() {
  console.log('✏️  Benchmarking PUT (create/update resource)...');
  const result = await runBenchmark({
    url: `http://127.0.0.1:${PORT}/bench/public/new`,
    method: 'PUT',
    headers: {
      'Content-Type': 'application/ld+json',
      'Authorization': `Bearer ${token}`
    },
    setupClient: (client) => {
      client.setBody(JSON.stringify({ '@id': '#test', 'http://example.org/v': putCounter++ }));
    }
  });
  return formatResult(result);
}

async function benchmarkPOST() {
  console.log('📝 Benchmarking POST (create in container)...');
  const result = await runBenchmark({
    url: `http://127.0.0.1:${PORT}/bench/public/`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/ld+json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ '@id': '#new', 'http://example.org/created': true })
  });
  return formatResult(result);
}

async function benchmarkOPTIONS() {
  console.log('🔍 Benchmarking OPTIONS (discovery)...');
  const result = await runBenchmark({
    url: `http://127.0.0.1:${PORT}/bench/public/item0.json`,
    method: 'OPTIONS'
  });
  return formatResult(result);
}

async function benchmarkHEAD() {
  console.log('📋 Benchmarking HEAD (metadata only)...');
  const result = await runBenchmark({
    url: `http://127.0.0.1:${PORT}/bench/public/item0.json`,
    method: 'HEAD'
  });
  return formatResult(result);
}

async function main() {
  console.log('🚀 JavaScript Solid Server Benchmark');
  console.log('=====================================');
  console.log(`Duration: ${DURATION}s per test, ${CONNECTIONS} concurrent connections\n`);

  await setup();

  const results = {};

  results['GET resource'] = await benchmarkGET();
  results['GET container'] = await benchmarkGETContainer();
  results['HEAD'] = await benchmarkHEAD();
  results['OPTIONS'] = await benchmarkOPTIONS();
  results['PUT'] = await benchmarkPUT();
  results['POST'] = await benchmarkPOST();

  console.log('\n📊 Results Summary');
  console.log('==================\n');

  // Print as table
  console.log('| Operation | Req/sec | Avg Latency | p99 Latency |');
  console.log('|-----------|---------|-------------|-------------|');
  for (const [op, data] of Object.entries(results)) {
    console.log(`| ${op.padEnd(13)} | ${String(data['Requests/sec']).padStart(7)} | ${data['Latency avg'].padStart(11)} | ${data['Latency p99'].padStart(11)} |`);
  }

  console.log('\n');

  await teardown();

  // Output JSON for README
  console.log('JSON results:');
  console.log(JSON.stringify(results, null, 2));
}

main().catch(console.error);
