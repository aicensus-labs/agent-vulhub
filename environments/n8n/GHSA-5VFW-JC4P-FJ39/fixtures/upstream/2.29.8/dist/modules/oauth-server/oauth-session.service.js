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
exports.OAuthSessionService = void 0;
const constants_1 = require("@n8n/constants");
const di_1 = require("@n8n/di");
const jwt_service_1 = require("../../services/jwt.service");
const COOKIE_NAME = 'n8n-oauth-session';
const SESSION_EXPIRY_MS = 10 * constants_1.Time.minutes.toMilliseconds;
let OAuthSessionService = class OAuthSessionService {
    constructor(jwtService) {
        this.jwtService = jwtService;
    }
    createSession(res, payload) {
        const sessionToken = this.jwtService.sign(payload, {
            expiresIn: '10m',
        });
        res.cookie(COOKIE_NAME, sessionToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: SESSION_EXPIRY_MS,
        });
    }
    verifySession(sessionToken) {
        return this.jwtService.verify(sessionToken);
    }
    clearSession(res) {
        res.clearCookie(COOKIE_NAME);
    }
    getSessionToken(cookies) {
        return cookies[COOKIE_NAME];
    }
};
exports.OAuthSessionService = OAuthSessionService;
exports.OAuthSessionService = OAuthSessionService = __decorate([
    (0, di_1.Service)(),
    __metadata("design:paramtypes", [jwt_service_1.JwtService])
], OAuthSessionService);
//# sourceMappingURL=oauth-session.service.js.map