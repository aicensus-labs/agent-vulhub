"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuthHelpers = void 0;
class OAuthHelpers {
    static buildSuccessRedirectUrl(redirectUri, code, state, issuer) {
        const targetUrl = new URL(redirectUri);
        targetUrl.searchParams.set('code', code);
        if (state) {
            targetUrl.searchParams.set('state', state);
        }
        targetUrl.searchParams.set('iss', issuer);
        return targetUrl.toString();
    }
    static buildErrorRedirectUrl(redirectUri, error, errorDescription, state, issuer) {
        const targetUrl = new URL(redirectUri);
        targetUrl.searchParams.set('error', error);
        targetUrl.searchParams.set('error_description', errorDescription);
        if (state) {
            targetUrl.searchParams.set('state', state);
        }
        targetUrl.searchParams.set('iss', issuer);
        return targetUrl.toString();
    }
}
exports.OAuthHelpers = OAuthHelpers;
//# sourceMappingURL=oauth.helpers.js.map