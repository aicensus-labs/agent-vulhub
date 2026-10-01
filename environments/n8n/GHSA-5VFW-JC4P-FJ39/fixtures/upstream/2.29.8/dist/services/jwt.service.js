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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JwtService = void 0;
const config_1 = require("@n8n/config");
const di_1 = require("@n8n/di");
const crypto_1 = require("crypto");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const n8n_core_1 = require("n8n-core");
let JwtService = class JwtService {
    constructor({ encryptionKey }, globalConfig) {
        this.jwtSecret = '';
        this.jwtSecretFromEnv = Boolean(globalConfig.userManagement.jwtSecret);
        this.jwtSecret = globalConfig.userManagement.jwtSecret;
        if (!this.jwtSecret) {
            let baseKey = '';
            for (let i = 0; i < encryptionKey.length; i += 2) {
                baseKey += encryptionKey[i];
            }
            this.jwtSecret = (0, crypto_1.createHash)('sha256').update(baseKey).digest('hex');
            globalConfig.userManagement.jwtSecret = this.jwtSecret;
        }
    }
    async initialize(repo) {
        if (this.jwtSecretFromEnv) {
            return;
        }
        const existing = await repo.findActiveByType('signing.jwt');
        if (existing) {
            this.jwtSecret = existing.value;
            return;
        }
        await repo.insertOrIgnore({
            type: 'signing.jwt',
            value: this.jwtSecret,
            status: 'active',
            algorithm: null,
        });
        const winner = await repo.findActiveByType('signing.jwt');
        if (winner)
            this.jwtSecret = winner.value;
    }
    sign(payload, options = {}) {
        return jsonwebtoken_1.default.sign(payload, this.jwtSecret, options);
    }
    decode(token) {
        return jsonwebtoken_1.default.decode(token);
    }
    verify(token, options = {}) {
        return jsonwebtoken_1.default.verify(token, this.jwtSecret, options);
    }
};
exports.JwtService = JwtService;
exports.JwtService = JwtService = __decorate([
    (0, di_1.Service)(),
    __metadata("design:paramtypes", [n8n_core_1.InstanceSettings, config_1.GlobalConfig])
], JwtService);
//# sourceMappingURL=jwt.service.js.map