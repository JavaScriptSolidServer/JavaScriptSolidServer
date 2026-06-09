import { startServer } from './server.js';
import { defaults } from './config.js';

const PORT = process.env.PORT || defaults.port;
const HOST = process.env.HOST || '0.0.0.0';

startServer(PORT, HOST).then(() => {
  console.log(`JavaScript Solid Server running at http://${HOST}:${PORT}`);
});
