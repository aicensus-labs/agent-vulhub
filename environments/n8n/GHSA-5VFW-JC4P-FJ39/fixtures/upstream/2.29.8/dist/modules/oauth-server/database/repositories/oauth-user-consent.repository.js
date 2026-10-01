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
exports.UserConsentRepository = void 0;
const di_1 = require("@n8n/di");
const typeorm_1 = require("@n8n/typeorm");
const oauth_user_consent_entity_1 = require("../entities/oauth-user-consent.entity");
let UserConsentRepository = class UserConsentRepository extends typeorm_1.Repository {
    constructor(dataSource) {
        super(oauth_user_consent_entity_1.UserConsent, dataSource.manager);
    }
    async findByUserWithClient(userId) {
        return await this.find({
            where: { userId },
            relations: ['client'],
            order: { grantedAt: 'DESC' },
        });
    }
};
exports.UserConsentRepository = UserConsentRepository;
exports.UserConsentRepository = UserConsentRepository = __decorate([
    (0, di_1.Service)(),
    __metadata("design:paramtypes", [typeorm_1.DataSource])
], UserConsentRepository);
//# sourceMappingURL=oauth-user-consent.repository.js.map