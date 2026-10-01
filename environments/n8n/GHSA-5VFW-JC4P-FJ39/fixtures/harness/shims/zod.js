"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
const passthrough = () => ({
  optional: () => passthrough(),
  default: () => passthrough(),
});
const z = {
  object: passthrough,
  string: () => passthrough(),
  boolean: () => passthrough(),
  array: () => passthrough(),
  enum: () => passthrough(),
  any: () => passthrough(),
  unknown: () => passthrough(),
  literal: () => passthrough(),
  nullish: () => passthrough(),
};
exports.z = z;
exports.default = z;
