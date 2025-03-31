# Vision

The goal of this project is to create a hyper-modern, performant, and minimalist JavaScript Solid server. While drawing inspiration from Node Solid Server (NSS), this new implementation will address its shortcomings and prioritize scalability, modularity, and developer usability.

## Key Objectives

- **Performance First:** Capable of handling enterprise-scale loads, targeting thousands to millions of users.
- **Minimalist Design:** Remove unused and experimental features; focus on what matters most.
- **Modularity:** Clear separation of identity, authentication, storage, and onboarding.
- **Developer Friendly:** Clean, well-documented, and extensible codebase that adheres to the Solid specification.
- **Modern Tooling:** Leverage async/await, native modules, fast HTTP servers like Fastify, and cutting-edge JavaScript runtimes.
- **HTTP Simplicity:** Prioritize simple HTTP/1.1 compatibility for maximum interoperability.
- **Frontend Agnostic:** Work with any frontend or application layer via standardized APIs.
- **Testable and CI Ready:** Fully integrated with Solid test suites and modern CI/CD pipelines.

---

# ARCHITECTURE

## Overview

The architecture is inspired by NSS but modernized and streamlined. Each subsystem is designed to operate independently and follow the single-responsibility principle.

### Components

- **HTTP Layer**

  - Fastify server
  - Routing and middleware based on HTTP verbs and Solid operations
  - Blazingly fast, with benchmarks from the start

- **Identity Provider (IDP)**

  - Handles Pod based WebIDs
  - Handles external WebIDs
  - Minimal by default, extendable via plugins

- **Authenticaion Module (AUthn)**

  - Handles WebID-based authentication, including WebID-TLS
  - OIDC-compliant with modular Authentication
  - Single sign-on including WebID-TLS

- **Authorization Module (Authz)**

  - Supports Web Access Control (WAC)
  - Token-based permissions model
  - Modular Authorization system

- **Storage Engine**

  - Modular backend adapters (e.g. file system, S3, memory)
  - POD-level quota management (optional)
  - Interoperable with existing Cloud

- **Account and Onboarding**
  - API-first registration
  - Public, private, invite modes
  - Extensible account templates

### Deployment Model

- Works as a single binary or serverless function
- Container-friendly (Docker, Deno, etc.)
- CLI for local dev setup and testing

### Separation of Concerns

- Each subsystem lives in its own module/package
- Clear boundaries between IDP and storage
- Frontend-independent API endpoints

### Compatibility

- Solid-compliant, LWS Compliant
- API parity with NSS where applicable
- API parity with CSS where applicable

---

# MVP Implementation

This is a minimal viable product (MVP) implementation of the JavaScriptSolid server. It includes the core components needed to demonstrate the concept while omitting some of the more complex features for simplicity.

## Getting Started

### Prerequisites

- Node.js 18 or higher

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/javascript-solid-server.git
cd javascript-solid-server

# Install dependencies
npm install
```

### Running the Server

```bash
# Start the server
npm start
```

The server will be available at http://localhost:3000 by default.

## Features Included in MVP

- **HTTP Server**: Based on Fastify for high performance
- **Basic Identity Provider**: Simple user registration and login with JWT tokens
- **Simple Authorization**: Basic implementation of WAC (Web Access Control)
- **File-based Storage**: Local filesystem storage for Solid resources
- **Basic Solid Protocol Support**: GET, PUT, DELETE, PATCH, and HEAD operations

## Features Omitted in MVP (to be added later)

1. WebID-TLS Authentication
2. Full OIDC implementation
3. Advanced WAC features and ACL file parsing
4. Quotas and resource limits
5. Advanced container management
6. SPARQL and N3 Patch support
7. Notification systems

## API Usage Examples

### User Registration

```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret", "email": "alice@example.com"}'
```

### Login

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret"}'
```

### Accessing Resources

```bash
# Get a resource
curl -X GET http://localhost:3000/alice/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Create or update a resource
curl -X PUT http://localhost:3000/alice/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: text/turtle" \
  -d '@prefix foaf: <http://xmlns.com/foaf/0.1/>. <#me> a foaf:Person; foaf:name "Alice".'
```

## Performance Benchmarking

This project includes a comprehensive benchmarking tool to measure server performance under various loads.

### Running the Benchmark

```bash
# Make sure the server is running in a separate terminal
npm start

# In another terminal, run the benchmark
npm run benchmark
```

The benchmark will:

1. Create multiple test users
2. Execute various operations (register, login, read, write, delete)
3. Measure response times for each operation type
4. Test different concurrency levels (1, 5, 10, 50, 100 users)
5. Calculate throughput (operations per second)

### Visualizing Results

After running the benchmark, you can generate a visual report:

```bash
# Generate an HTML report with charts
npm run visualize benchmark-report-[timestamp].json
```

Open the generated HTML file in a browser to see:

- Average response times for each operation type
- Throughput metrics at different concurrency levels
- Visual charts for easy performance analysis

### Customizing Benchmarks

You can customize the benchmark parameters in `benchmark.js`:

- Concurrent users levels
- Operations per user
- Test duration
- Test user credentials

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
