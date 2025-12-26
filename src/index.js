import { startServer } from './server.js';

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

startServer(PORT, HOST).then(() => {
  console.log(`JavaScript Solid Server running at http://${HOST}:${PORT}`);
});
