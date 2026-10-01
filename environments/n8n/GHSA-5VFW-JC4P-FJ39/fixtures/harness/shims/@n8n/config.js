"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
class GlobalConfig {
  constructor() {
    this.endpoints = { mcp: "mcp", rest: "rest", webhook: "webhook", webhookTest: "webhook-test" };
    this.host = "127.0.0.1";
    this.port = 5678;
    this.protocol = "http";
    this.path = "";
    this.editorBaseUrl = "http://127.0.0.1:5678";
    this.userManagement = { jwtSecret: "lab-synthetic-jwt-secret" };
    this.deployment = {};
  }
}
exports.GlobalConfig = GlobalConfig;
