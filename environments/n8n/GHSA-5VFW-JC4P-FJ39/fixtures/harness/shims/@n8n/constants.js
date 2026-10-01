"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
exports.Time = {
  hours: { toSeconds: 3600, toMilliseconds: 3600000 },
  days: { toSeconds: 86400, toMilliseconds: 86400000 },
  minutes: { toSeconds: 60, toMilliseconds: 60000 },
  seconds: { toMilliseconds: 1000 },
};
