"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
class InvalidGrantError extends Error {}
class InvalidTokenError extends Error {}
// The MCP SDK error hierarchy the pinned modules extend. Only the class shape is
// needed: the lab asserts on the upstream services' own error identity.
class OAuthError extends Error {
  constructor(message, errorCode, statusCode) {
    super(message);
    this.errorCode = errorCode;
    this.statusCode = statusCode;
  }
}
class ServerError extends OAuthError {}
class InvalidRequestError extends OAuthError {}
class InvalidClientMetadataError extends OAuthError {}
class InvalidScopeError extends OAuthError {}
class InsufficientScopeError extends OAuthError {}
class InvalidTargetError extends OAuthError {}
class AuthorizationServerMetadataError extends OAuthError {}
class TemporarilyUnavailableError extends OAuthError {}
exports.OAuthError = OAuthError;
exports.ServerError = ServerError;
exports.InvalidRequestError = InvalidRequestError;
exports.InvalidClientMetadataError = InvalidClientMetadataError;
exports.InvalidScopeError = InvalidScopeError;
exports.InsufficientScopeError = InsufficientScopeError;
exports.InvalidTargetError = InvalidTargetError;
exports.AuthorizationServerMetadataError = AuthorizationServerMetadataError;
exports.TemporarilyUnavailableError = TemporarilyUnavailableError;
exports.InvalidGrantError = InvalidGrantError;
exports.InvalidTokenError = InvalidTokenError;
