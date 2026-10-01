"use strict";
// Adapter, not upstream code: node does not expose a default CommonJS
// `reflect-metadata` shim and the pinned modules' decorator helpers tolerate its
// absence. This keeps `require("reflect-metadata")` a no-op.
if (typeof Reflect.metadata !== "function") Reflect.metadata = () => () => undefined;
if (typeof Reflect.defineMetadata !== "function") {
  Reflect.defineMetadata = () => undefined;
  Reflect.getMetadata = () => undefined;
  Reflect.hasMetadata = () => false;
}
