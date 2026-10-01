'use strict';

/*
 * Build-time attestation for GHSA-8G7G-HMWM-6RV2.
 *
 * Run as `node /lab/build-check.cjs <variant>` inside the image. It fails the
 * build unless the pinned upstream release, the exact compiled entry point and
 * the correct side of the fix are baked in, and unless the locked runtime
 * closure actually loads. Expected hashes are the sha256 of the upstream
 * `dist/services/n8n-api-client.js` bytes published in n8n-mcp 2.50.0 / 2.50.1.
 */

const fs = require('fs');
const crypto = require('crypto');

const variant = process.argv[2];
const expected = {
  vulnerable: {
    version: '2.50.0',
    apiClient: 'd917e77627f5b590874e8dbaabda013c0208d958b4732eb80d223d06f63cbcc1',
    pathSegmentGuard: false,
  },
  patched: {
    version: '2.50.1',
    apiClient: 'f596f39451cf47ce8538df40ad5678118fc6700306b8a6c01eb5b5a642f2bb06',
    pathSegmentGuard: true,
  },
}[variant];

if (!expected) {
  throw new Error('unknown VARIANT ' + variant);
}

const root = '/lab/upstream/package';
const pkg = require(root + '/package.json');
if (pkg.version !== expected.version) {
  throw new Error('installed n8n-mcp ' + pkg.version + ', expected ' + expected.version);
}

const source = fs.readFileSync(root + '/dist/services/n8n-api-client.js');
const digest = crypto.createHash('sha256').update(source).digest('hex');
if (digest !== expected.apiClient) {
  throw new Error('n8n-api-client.js ' + digest + ', expected ' + expected.apiClient);
}

// 2.50.1 routes every caller-supplied path segment through validation-schemas;
// 2.50.0 interpolates the id verbatim and never imports that module.
const guarded = source.toString('utf8').includes('validation-schemas');
if (guarded !== expected.pathSegmentGuard) {
  throw new Error('path-segment guard present=' + guarded + ', expected ' + expected.pathSegmentGuard);
}

// The reproduction resolves axios and zod through NODE_PATH, so prove that both
// the direct dependencies and the full transitive closure are installed.
for (const dep of ['axios', 'zod', 'follow-redirects', 'form-data', 'proxy-from-env']) {
  require('/lab/vendor/node_modules/' + dep + '/package.json');
}

const { N8nApiClient } = require(root + '/dist/services/n8n-api-client.js');
const { MutationTracker } = require(root + '/dist/telemetry/mutation-tracker.js');
if (typeof N8nApiClient !== 'function' || typeof MutationTracker !== 'function') {
  throw new Error('pinned entry points did not load');
}

const axiosVersion = require('axios/package.json').version;
const zodVersion = require('zod/package.json').version;
console.log(variant + ' n8n-mcp ' + pkg.version + ' installed offline with axios '
  + axiosVersion + ' and zod ' + zodVersion);
