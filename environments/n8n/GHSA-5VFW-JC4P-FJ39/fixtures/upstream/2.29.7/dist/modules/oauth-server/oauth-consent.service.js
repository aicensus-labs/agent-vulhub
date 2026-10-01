"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuthConsentService = void 0;
const backend_common_1 = require("@n8n/backend-common");
const di_1 = require("@n8n/di");
const n8n_workflow_1 = require("n8n-workflow");
const oauth_client_repository_1 = require("./database/repositories/oauth-client.repository");
const oauth_user_consent_repository_1 = require("./database/repositories/oauth-user-consent.repository");
const oauth_authorization_code_service_1 = require("./oauth-authorization-code.service");
const oauth_session_service_1 = require("./oauth-session.service");
const oauth_helpers_1 = require("./oauth.helpers");
const protected_resource_registry_1 = require("../../services/protected-resource.registry");
const url_service_1 = require("../../services/url.service");
let OAuthConsentService = class OAuthConsentService {
    constructor(logger, oauthSessionService, oauthClientRepository, userConsentRepository, authorizationCodeService, protectedResourceRegistry, urlService) {
        this.logger = logger;
        this.oauthSessionService = oauthSessionService;
        this.oauthClientRepository = oauthClientRepository;
        this.userConsentRepository = userConsentRepository;
        this.authorizationCodeService = authorizationCodeService;
        this.protectedResourceRegistry = protectedResourceRegistry;
        this.urlService = urlService;
    }
    async getConsentDetails(sessionToken) {
        try {
            const sessionPayload = this.oauthSessionService.verifySession(sessionToken);
            const client = await this.oauthClientRepository.findOne({
                where: { id: sessionPayload.clientId },
            });
            if (!client) {
                return null;
            }
            if (sessionPayload.resource) {
                const resource = await this.protectedResourceRegistry.getByResourceUrl(sessionPayload.resource);
                if (!resource) {
                    return { ok: false, reason: 'resource_unavailable' };
                }
                return {
                    ok: true,
                    clientName: client.name,
                    clientId: client.id,
                    resourceName: resource.displayName,
                    redirectUri: sessionPayload.redirectUri,
                };
            }
            return {
                ok: true,
                clientName: client.name,
                clientId: client.id,
                redirectUri: sessionPayload.redirectUri,
            };
        }
        catch (error) {
            this.logger.error('Error getting consent details', { error });
            return null;
        }
    }
    async handleConsentDecision(sessionToken, userId, approved) {
        let sessionPayload;
        try {
            sessionPayload = this.oauthSessionService.verifySession(sessionToken);
        }
        catch (error) {
            throw new n8n_workflow_1.UserError('Invalid or expired session');
        }
        const issuer = this.urlService.getInstanceBaseUrl();
        if (!approved) {
            const redirectUrl = oauth_helpers_1.OAuthHelpers.buildErrorRedirectUrl(sessionPayload.redirectUri, 'access_denied', 'User denied the authorization request', sessionPayload.state, issuer);
            this.logger.info('Consent denied', {
                clientId: sessionPayload.clientId,
                userId,
            });
            return { redirectUrl };
        }
        await this.userConsentRepository.upsert({
            userId,
            clientId: sessionPayload.clientId,
            grantedAt: Date.now(),
        }, ['userId', 'clientId']);
        const code = await this.authorizationCodeService.createAuthorizationCode(sessionPayload.clientId, userId, sessionPayload.redirectUri, sessionPayload.codeChallenge, sessionPayload.state, sessionPayload.resource);
        const successRedirectUrl = oauth_helpers_1.OAuthHelpers.buildSuccessRedirectUrl(sessionPayload.redirectUri, code, sessionPayload.state, issuer);
        this.logger.info('Consent approved', {
            clientId: sessionPayload.clientId,
            userId,
        });
        return { redirectUrl: successRedirectUrl };
    }
};
exports.OAuthConsentService = OAuthConsentService;
exports.OAuthConsentService = OAuthConsentService = __decorate([
    (0, di_1.Service)(),
    __metadata("design:paramtypes", [backend_common_1.Logger,
        oauth_session_service_1.OAuthSessionService,
        oauth_client_repository_1.OAuthClientRepository,
        oauth_user_consent_repository_1.UserConsentRepository,
        oauth_authorization_code_service_1.OAuthAuthorizationCodeService,
        protected_resource_registry_1.ProtectedResourceRegistry,
        url_service_1.UrlService])
], OAuthConsentService);
//# sourceMappingURL=oauth-consent.service.js.map