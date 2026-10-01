"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
class UserError extends Error {}
class UnexpectedError extends Error {}
class OperationalError extends Error {}
class ApplicationError extends Error {
  constructor(message, options) { super(message); this.options = options; }
}
// n8n's error base class. The lab only needs the shape: `message`, `cause`, and
// instance identity so the upstream services' instanceof checks behave.
class BaseError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "BaseError";
  }
}
const jsonParse = (value) => JSON.parse(value);
const ensureError = (error) => (error instanceof Error ? error : new Error(String(error)));
exports.UserError = UserError;
exports.UnexpectedError = UnexpectedError;
exports.OperationalError = OperationalError;
exports.ApplicationError = ApplicationError;
exports.BaseError = BaseError;
exports.jsonParse = jsonParse;
exports.ensureError = ensureError;
