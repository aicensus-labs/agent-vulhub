"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
const registry = new Map();
const identity = () => (target) => target;
class Container {
  static get(token) {
    if (!registry.has(token)) throw new Error("lab adapter: no provider for " + String(token));
    return registry.get(token);
  }
  static set(token, value) { registry.set(token, value); return value; }
  static has(token) { return registry.has(token); }
  static reset() { registry.clear(); }
}
exports.Container = Container;
exports.Service = identity;
exports.Injectable = identity;
exports.Module = identity;
exports.Inject = () => () => undefined;
exports.Optional = () => () => undefined;
exports.OnShutdown = () => () => undefined;
exports.OnInit = () => () => undefined;
exports.OnBeforeShutdown = () => () => undefined;
exports.OnBeforeApplicationShutdown = () => () => undefined;
