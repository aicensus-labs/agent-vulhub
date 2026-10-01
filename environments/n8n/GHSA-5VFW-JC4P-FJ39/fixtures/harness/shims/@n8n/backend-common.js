"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
class Logger {
  constructor() { this.scopes = []; }
  scoped() { return this; }
  debug() {} info() {} warn() {} error() {}
  static getInstance() { return new Logger(); }
}
class ModuleRegistry {
  constructor() { this.modules = new Set(); }
  isActive(name) { return this.modules.has(name); }
}
class InstanceSettings {
  constructor() { this.encryptionKey = "lab-synthetic-encryption-key"; }
}
const ensureError = (error) => (error instanceof Error ? error : new Error(String(error)));
exports.Logger = Logger;
exports.ModuleRegistry = ModuleRegistry;
exports.InstanceSettings = InstanceSettings;
exports.ensureError = ensureError;
