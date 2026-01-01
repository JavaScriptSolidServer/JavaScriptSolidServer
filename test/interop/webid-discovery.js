/**
 * Simulate what NSS does: fetch WebID profile and discover oidcIssuer
 */
const fetch = require('node-fetch');

const WEBID = 'https://melvincarvalho.com/#me';

async function test() {
  console.log('=== WebID Profile Discovery Test ===\n');
  
  // Fetch WebID profile (what NSS does)
  console.log('1. Fetching WebID profile:', WEBID);
  
  const response = await fetch(WEBID.split('#')[0], {
    headers: {
      'Accept': 'text/turtle, application/ld+json, */*',
    },
  });
  
  console.log('   Status:', response.status);
  console.log('   Content-Type:', response.headers.get('content-type'));
  
  const body = await response.text();
  console.log('   Content length:', body.length);
  
  // Check for solid:oidcIssuer
  console.log('\n2. Looking for solid:oidcIssuer...');
  
  // Look for the triple
  const oidcIssuerMatch = body.match(/solid:oidcIssuer\s+<([^>]+)>/);
  if (oidcIssuerMatch) {
    console.log('   Found: solid:oidcIssuer <' + oidcIssuerMatch[1] + '>');
  } else {
    console.log('   Pattern 1 not found, trying other patterns...');
    
    // Try full URI pattern
    const fullUriMatch = body.match(/http:\/\/www\.w3\.org\/ns\/solid\/terms#oidcIssuer[^<]+<([^>]+)>/);
    if (fullUriMatch) {
      console.log('   Found via full URI: <' + fullUriMatch[1] + '>');
    }
  }
  
  // Show relevant lines
  console.log('\n3. Relevant lines from profile:');
  const lines = body.split('\n');
  for (const line of lines) {
    if (line.includes('oidcIssuer') || line.includes('solid:') || line.includes('@prefix solid')) {
      console.log('   ' + line.trim());
    }
  }
  
  // Also check CORS headers
  console.log('\n4. CORS headers:');
  console.log('   Access-Control-Allow-Origin:', response.headers.get('access-control-allow-origin') || 'NOT SET');
  console.log('   Access-Control-Allow-Credentials:', response.headers.get('access-control-allow-credentials') || 'NOT SET');
}

test().catch(console.error);
