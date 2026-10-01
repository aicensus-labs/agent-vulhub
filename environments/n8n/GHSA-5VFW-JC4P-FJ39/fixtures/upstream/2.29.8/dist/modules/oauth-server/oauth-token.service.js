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
exports.OAuthTokenService = void 0;
const errors_js_1 = require("@modelcontextprotocol/sdk/server/auth/errors.js");
const backend_common_1 = require("@n8n/backend-common");
const constants_1 = require("@n8n/constants");
const db_1 = require("@n8n/db");
const di_1 = require("@n8n/di");
const typeorm_1 = require("@n8n/typeorm");
const n8n_workflow_1 = require("n8n-workflow");
const node_crypto_1 = require("node:crypto");
const oauth_access_token_entity_1 = require("./database/entities/oauth-access-token.entity");
const oauth_refresh_token_entity_1 = require("./database/entities/oauth-refresh-token.entity");
const oauth_access_token_repository_1 = require("./database/repositories/oauth-access-token.repository");
const oauth_refresh_token_repository_1 = require("./database/repositories/oauth-refresh-token.repository");
const protected_resource_registry_1 = require("../../services/protected-resource.registry");
const oauth_errors_1 = require("./oauth.errors");
const jwt_service_1 = require("../../services/jwt.service");
let OAuthTokenService = class OAuthTokenService {
    constructor(logger, jwtService, userRepository, accessTokenRepository, refreshTokenRepository, resourceRegistry) {
        this.logger = logger;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.resourceRegistry = resourceRegistry;
        this.ACCESS_TOKEN_EXPIRY_SECONDS = 1 * constants_1.Time.hours.toSeconds;
        this.REFRESH_TOKEN_EXPIRY_MS = 30 * constants_1.Time.days.toMilliseconds;
    }
    getAccessTokenExpirySeconds() {
        return this.ACCESS_TOKEN_EXPIRY_SECONDS;
    }
    generateTokenPair(userId, clientId, resource) {
        const audience = resource ?? this.resourceRegistry.getDefaultResource()?.getResourceUrl();
        if (!audience) {
            throw new n8n_workflow_1.UnexpectedError('Cannot mint an OAuth access token: no resource requested and no default protected resource is registered');
        }
        const accessToken = this.jwtService.sign({
            sub: userId,
            aud: audience,
            client_id: clientId,
            jti: (0, node_crypto_1.randomUUID)(),
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + this.ACCESS_TOKEN_EXPIRY_SECONDS,
            meta: {
                isOAuth: true,
            },
        });
        const refreshToken = (0, node_crypto_1.randomBytes)(32).toString('hex');
        return { accessToken, refreshToken };
    }
    async saveTokenPair(accessToken, refreshToken, clientId, userId) {
        await this.accessTokenRepository.manager.transaction(async (transactionManager) => {
            await transactionManager.insert(this.accessTokenRepository.target, {
                token: accessToken,
                clientId,
                userId,
            });
            await transactionManager.insert(this.refreshTokenRepository.target, {
                token: refreshToken,
                clientId,
                userId,
                expiresAt: Date.now() + this.REFRESH_TOKEN_EXPIRY_MS,
            });
        });
    }
    async validateAndRotateRefreshToken(refreshToken, clientId, resource) {
        return await (0, db_1.withTransaction)(this.refreshTokenRepository.manager, undefined, async (trx) => {
            const now = Date.now();
            const refreshTokenRecord = await trx.findOne(oauth_refresh_token_entity_1.RefreshToken, {
                where: {
                    token: refreshToken,
                    clientId,
                },
            });
            if (!refreshTokenRecord) {
                throw new errors_js_1.InvalidGrantError('Invalid refresh token');
            }
            const result = await trx.delete(oauth_refresh_token_entity_1.RefreshToken, {
                token: refreshToken,
                clientId,
                expiresAt: (0, typeorm_1.MoreThanOrEqual)(now),
            });
            const numAffected = result.affected ?? 0;
            if (numAffected < 1) {
                throw new errors_js_1.InvalidGrantError('Invalid refresh token');
            }
            const { accessToken, refreshToken: newRefreshToken } = this.generateTokenPair(refreshTokenRecord.userId, clientId, resource);
            await trx.insert(oauth_access_token_entity_1.AccessToken, {
                token: accessToken,
                clientId,
                userId: refreshTokenRecord.userId,
            });
            await trx.insert(oauth_refresh_token_entity_1.RefreshToken, {
                token: newRefreshToken,
                clientId,
                userId: refreshTokenRecord.userId,
                expiresAt: now + this.REFRESH_TOKEN_EXPIRY_MS,
            });
            this.logger.info('Refresh token rotated and new access token issued', {
                clientId,
                userId: refreshTokenRecord.userId,
            });
            return {
                access_token: accessToken,
                token_type: 'Bearer',
                expires_in: this.ACCESS_TOKEN_EXPIRY_SECONDS,
                refresh_token: newRefreshToken,
            };
        });
    }
    async verifyAccessToken(token, expectedAudience) {
        return await this.verifyTokenWithAudiences(token, await this.getAllowedAudiences(expectedAudience));
    }
    async verifyTokenWithAudiences(token, allowedAudiences) {
        let decoded;
        try {
            decoded = this.verifyJwtWithAllowedAudiences(token, allowedAudiences);
        }
        catch (error) {
            throw new oauth_errors_1.JWTVerificationError();
        }
        const clientId = this.getStringClaim(decoded, 'client_id');
        const userId = this.getStringClaim(decoded, 'sub');
        if (!clientId || !userId) {
            throw new oauth_errors_1.JWTVerificationError();
        }
        const accessTokenRecord = await this.accessTokenRepository.findOne({
            where: { token },
        });
        if (!accessTokenRecord) {
            throw new oauth_errors_1.AccessTokenNotFoundError();
        }
        return {
            token,
            clientId,
            scopes: [],
            extra: {
                userId,
            },
        };
    }
    async verifyOAuthAccessToken(token, expectedAudience) {
        try {
            const resource = await this.getResourceByAudience(expectedAudience);
            if (expectedAudience && !resource) {
                return { user: null, context: { reason: 'insufficient_scope', auth_type: 'oauth' } };
            }
            const authInfo = await this.verifyTokenWithAudiences(token, this.audiencesForResource(resource, expectedAudience));
            const userId = authInfo.extra && typeof authInfo.extra === 'object'
                ? this.getStringClaim(authInfo.extra, 'userId')
                : null;
            if (!userId) {
                return { user: null, context: { reason: 'user_id_not_in_auth_info', auth_type: 'oauth' } };
            }
            const user = await this.userRepository.findOne({
                where: { id: userId },
                relations: ['role'],
            });
            if (!user) {
                return { user: null, context: { reason: 'user_not_found', auth_type: 'oauth' } };
            }
            if (resource && !(await resource.authorize(user))) {
                this.logger.warn('OAuth token denied: user lacks execute access', {
                    userId: user.id,
                    expectedAudience,
                });
                return { user: null, context: { reason: 'insufficient_scope', auth_type: 'oauth' } };
            }
            return { user, authType: 'oauth' };
        }
        catch (error) {
            const errorForSure = (0, n8n_workflow_1.ensureError)(error);
            const reason = errorForSure instanceof oauth_errors_1.JWTVerificationError
                ? 'invalid_token'
                : errorForSure instanceof oauth_errors_1.AccessTokenNotFoundError
                    ? 'token_not_found_in_db'
                    : 'unknown_error';
            return {
                user: null,
                context: {
                    reason,
                    auth_type: 'oauth',
                    error_details: errorForSure.message,
                },
            };
        }
    }
    async revokeAccessToken(token, clientId) {
        const result = await this.accessTokenRepository.delete({
            token,
            clientId,
        });
        const revoked = (result.affected ?? 0) > 0;
        if (revoked) {
            this.logger.info('Access token revoked', { clientId });
        }
        return revoked;
    }
    async revokeRefreshToken(token, clientId) {
        const result = await this.refreshTokenRepository.delete({
            token,
            clientId,
        });
        const revoked = (result.affected ?? 0) > 0;
        if (revoked) {
            this.logger.info('Refresh token revoked', { clientId });
        }
        return revoked;
    }
    async getAllowedAudiences(expectedAudience) {
        const resource = expectedAudience
            ? await this.resourceRegistry.getByResourceUrl(expectedAudience)
            : undefined;
        return this.audiencesForResource(resource, expectedAudience);
    }
    audiencesForResource(resource, expectedAudience) {
        if (expectedAudience) {
            return resource ? resource.getAudiences() : [expectedAudience];
        }
        return this.resourceRegistry.getAllAudiences();
    }
    async getResourceByAudience(expectedAudience) {
        if (!expectedAudience) {
            return this.resourceRegistry.getDefaultResource();
        }
        return await this.resourceRegistry.getByResourceUrl(expectedAudience);
    }
    verifyJwtWithAllowedAudiences(token, audiences) {
        try {
            return this.jwtService.verify(token, {
                audience: audiences,
            });
        }
        catch (error) {
            for (const audience of audiences) {
                try {
                    return this.jwtService.verify(token, { audience });
                }
                catch {
                    continue;
                }
            }
            throw error;
        }
    }
    getStringClaim(payload, claim) {
        if (!payload || typeof payload !== 'object')
            return null;
        const claimValue = payload[claim];
        return typeof claimValue === 'string' ? claimValue : null;
    }
};
exports.OAuthTokenService = OAuthTokenService;
exports.OAuthTokenService = OAuthTokenService = __decorate([
    (0, di_1.Service)(),
    __metadata("design:paramtypes", [backend_common_1.Logger,
        jwt_service_1.JwtService,
        db_1.UserRepository,
        oauth_access_token_repository_1.AccessTokenRepository,
        oauth_refresh_token_repository_1.RefreshTokenRepository,
        protected_resource_registry_1.ProtectedResourceRegistry])
], OAuthTokenService);
//# sourceMappingURL=oauth-token.service.js.map