"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
class InstanceSettings {
  constructor() { this.encryptionKey = "lab-synthetic-encryption-key"; }
}
exports.InstanceSettings = InstanceSettings;
