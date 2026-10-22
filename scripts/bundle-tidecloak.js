// Bundles @tidecloak/js into one browser ES module. The SDK's dependencies use bundler-style
// extensionless imports, so a browser cannot load them straight from node_modules. This is the only
// build step, and it runs on `npm install`; the app's own code is still served as-is.
const path = require('path');
const fs = require('fs');

const out = path.join(__dirname, '..', 'app', 'public', 'vendor');
fs.mkdirSync(out, { recursive: true });
require('esbuild').buildSync({
  stdin: { contents: "export { IAMService } from '@tidecloak/js';", resolveDir: path.join(__dirname, '..'), loader: 'js' },
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2020',
  minify: true,
  outfile: path.join(out, 'tidecloak.js'),
  logLevel: 'warning'
});
console.log('[bundle] app/public/vendor/tidecloak.js ready');
