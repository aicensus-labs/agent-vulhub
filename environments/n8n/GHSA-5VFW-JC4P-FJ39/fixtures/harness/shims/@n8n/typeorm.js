"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
const In = (values) => ({ __operator: "in", values });
const MoreThanOrEqual = (value) => ({ __operator: "moreThanOrEqual", value });
const Equal = (value) => ({ __operator: "equal", value });
// Column/Entity/Index/... are pure metadata decorators in typeorm; the lab keeps
// its rows in memory, so registering metadata is all they have to do.
const decorator = () => () => undefined;
class Repository {
  constructor(target, manager) {
    this.target = target;
    this.manager = manager || { transaction: async (run) => await run({ insert: async () => undefined }) };
  }
}
class DataSource {
  constructor() { this.manager = {}; }
}
exports.In = In;
exports.MoreThanOrEqual = MoreThanOrEqual;
exports.Equal = Equal;
exports.Repository = Repository;
exports.DataSource = DataSource;
for (const name of ["Column", "Entity", "Index", "ManyToOne", "OneToMany", "ManyToMany",
                    "OneToOne", "JoinColumn", "PrimaryColumn", "PrimaryGeneratedColumn",
                    "Unique", "CreateDateColumn", "UpdateDateColumn", "DeleteDateColumn",
                    "BeforeInsert", "BeforeUpdate", "AfterLoad", "RelationId", "VirtualColumn"]) {
  exports[name] = decorator;
}
