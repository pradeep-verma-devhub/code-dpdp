export { createApp, startServer } from './main.js';
import { startServer } from './main.js';

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}
