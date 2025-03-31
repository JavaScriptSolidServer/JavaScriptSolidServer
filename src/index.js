import { startServer } from './http/server.js';

// Start the server
const PORT = process.env.PORT || 3000;
startServer(PORT).then(server => {
  console.log(`JavaScript Solid Server running on port ${PORT}`);
});
