import fetch from 'node-fetch';
import { performance } from 'perf_hooks';
import { promises as fs } from 'fs';
import path from 'path';

// Configuration
const config = {
  baseUrl: 'http://nostr.social:3000',
  concurrentUsers: [1, 5, 10, 50, 100], // Different concurrency levels to test
  operations: 100, // Operations per user
  testDuration: 30000, // 30 seconds per test
  testUserPrefix: 'testuser',
  testPassword: 'benchmark123',
  results: {
    registerTime: [],
    loginTime: [],
    readTime: [],
    writeTime: [],
    deleteTime: [],
    throughput: []
  }
};

// Store tokens for authenticated requests
const tokens = new Map();

// Utility function to measure execution time
async function measureTime (fn) {
  const start = performance.now();
  const result = await fn();
  const end = performance.now();
  return { result, time: end - start };
}

// Register a test user
async function registerUser (username) {
  const { result, time } = await measureTime(async () => {
    const response = await fetch(`${config.baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password: config.testPassword,
        email: `${username}@benchmark.test`
      })
    });
    return response.json();
  });

  config.results.registerTime.push(time);
  return result;
}

// Login a test user
async function loginUser (username) {
  const { result, time } = await measureTime(async () => {
    const response = await fetch(`${config.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password: config.testPassword
      })
    });
    return response.json();
  });

  config.results.loginTime.push(time);

  if (result.id_token) {
    tokens.set(username, result.id_token);
  }

  return result;
}

// Create a resource
async function createResource (username, resourcePath, content = null) {
  const token = tokens.get(username);
  if (!token) throw new Error(`No token for user ${username}`);

  const turtleContent = content || `
    @prefix foaf: <http://xmlns.com/foaf/0.1/>.
    <#me> a foaf:Person;
      foaf:name "${username}";
      foaf:mbox <mailto:${username}@benchmark.test>.
  `;

  const { result, time } = await measureTime(async () => {
    const response = await fetch(`${config.baseUrl}/${username}/${resourcePath}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'text/turtle',
        'Authorization': `Bearer ${token}`
      },
      body: turtleContent
    });
    return response.status;
  });

  config.results.writeTime.push(time);
  return result;
}

// Read a resource
async function readResource (username, resourcePath) {
  const token = tokens.get(username);
  if (!token) throw new Error(`No token for user ${username}`);

  const { result, time } = await measureTime(async () => {
    const response = await fetch(`${config.baseUrl}/${username}/${resourcePath}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    return response.status;
  });

  config.results.readTime.push(time);
  return result;
}

// Delete a resource
async function deleteResource (username, resourcePath) {
  const token = tokens.get(username);
  if (!token) throw new Error(`No token for user ${username}`);

  const { result, time } = await measureTime(async () => {
    const response = await fetch(`${config.baseUrl}/${username}/${resourcePath}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    return response.status;
  });

  config.results.deleteTime.push(time);
  return result;
}

// Run benchmark for specific concurrency
async function runBenchmark (concurrentUsers) {
  console.log(`\n=== Running benchmark with ${concurrentUsers} concurrent users ===`);

  // Create test users
  console.log('Creating test users...');
  const users = [];
  for (let i = 0; i < concurrentUsers; i++) {
    const username = `${config.testUserPrefix}${i}`;
    users.push(username);
    await registerUser(username);
    await loginUser(username);
  }

  // Prepare operation queue (read/write/delete)
  const operations = [];
  for (const username of users) {
    for (let i = 0; i < config.operations; i++) {
      const resourcePath = `benchmark/resource${i}.ttl`;
      operations.push(async () => await createResource(username, resourcePath));
      operations.push(async () => await readResource(username, resourcePath));
      operations.push(async () => await deleteResource(username, resourcePath));
    }
  }

  // Run operations with measured throughput
  console.log(`Starting operations (${operations.length} total)...`);
  const startTime = performance.now();
  let completedOps = 0;
  const endTime = startTime + config.testDuration;

  // Create chunks of operations to run in parallel
  const chunks = [];
  const chunkSize = operations.length > 100 ? 100 : operations.length;

  for (let i = 0; i < operations.length; i += chunkSize) {
    chunks.push(operations.slice(i, i + chunkSize));
  }

  for (const chunk of chunks) {
    if (performance.now() >= endTime) break;

    await Promise.all(chunk.map(async (operation) => {
      if (performance.now() < endTime) {
        await operation();
        completedOps++;
      }
    }));
  }

  // Calculate throughput (ops/sec)
  const actualDuration = Math.min(performance.now() - startTime, config.testDuration);
  const throughput = (completedOps / actualDuration) * 1000;
  config.results.throughput.push({
    concurrentUsers,
    operations: completedOps,
    duration: actualDuration,
    throughput
  });

  console.log(`Completed ${completedOps} operations in ${actualDuration.toFixed(2)}ms`);
  console.log(`Throughput: ${throughput.toFixed(2)} operations/second`);
}

// Generate report
async function generateReport () {
  // Calculate averages
  const averages = {
    register: calculateAverage(config.results.registerTime),
    login: calculateAverage(config.results.loginTime),
    read: calculateAverage(config.results.readTime),
    write: calculateAverage(config.results.writeTime),
    delete: calculateAverage(config.results.deleteTime)
  };

  // Create report
  const report = {
    timestamp: new Date().toISOString(),
    server: config.baseUrl,
    testDuration: config.testDuration,
    averageResponseTimes: averages,
    throughputResults: config.results.throughput
  };

  // Save report to file
  await fs.writeFile(
    `benchmark-report-${new Date().toISOString().replace(/:/g, '-')}.json`,
    JSON.stringify(report, null, 2)
  );

  // Display summary
  console.log('\n=== BENCHMARK RESULTS ===');
  console.log('Average Response Times (ms):');
  console.log(`  Register: ${averages.register.toFixed(2)} ms`);
  console.log(`  Login: ${averages.login.toFixed(2)} ms`);
  console.log(`  Read: ${averages.read.toFixed(2)} ms`);
  console.log(`  Write: ${averages.write.toFixed(2)} ms`);
  console.log(`  Delete: ${averages.delete.toFixed(2)} ms`);

  console.log('\nThroughput Results:');
  config.results.throughput.forEach(result => {
    console.log(`  ${result.concurrentUsers} users: ${result.throughput.toFixed(2)} ops/sec`);
  });

  console.log('\nReport saved to file.');
}

// Calculate average of an array
function calculateAverage (array) {
  if (array.length === 0) return 0;
  return array.reduce((sum, value) => sum + value, 0) / array.length;
}

// Main benchmark function
async function startBenchmark () {
  console.log('=== JavaScript Solid Server Benchmark ===');
  console.log(`Server URL: ${config.baseUrl}`);
  console.log(`Test Duration: ${config.testDuration / 1000} seconds per concurrency level`);

  try {
    // Check if server is running
    const response = await fetch(config.baseUrl);
    if (response.status < 200 || response.status >= 500) {
      throw new Error(`Server responded with status ${response.status}`);
    }
  } catch (error) {
    console.error('Error connecting to server:', error.message);
    console.error('Please make sure the server is running before starting the benchmark.');
    return;
  }

  // Run tests for each concurrency level
  for (const concurrentUsers of config.concurrentUsers) {
    await runBenchmark(concurrentUsers);
  }

  // Generate final report
  await generateReport();
}

// Start the benchmark
startBenchmark().catch(error => {
  console.error('Benchmark error:', error);
}); 
