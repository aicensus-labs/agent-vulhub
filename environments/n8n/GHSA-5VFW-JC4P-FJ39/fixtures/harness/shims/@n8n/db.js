"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
const User = class User {};
const Project = class Project {};
const SharedWorkflow = class SharedWorkflow {};
const SharedCredentials = class SharedCredentials {};
const WorkflowEntity = class WorkflowEntity {};
const GLOBAL_ADMIN_ROLE = { slug: "global:admin" };
const GLOBAL_OWNER_ROLE = { slug: "global:owner" };
const GLOBAL_MEMBER_ROLE = { slug: "global:member" };
class WorkflowRepository {}
class UserRepository {}
class SharedWorkflowRepository {}
class ProjectRepository {}
class CredentialsRepository {}
class WebhookRepository {}
const withTransaction = async (manager, _isolation, run) => await run(manager);
// Base entity classes the pinned entities extend; the lab keeps rows in memory
// and never persists them, so the base classes only have to exist.
class WithTimestamps {}
class WithSoftDelete {}
const JsonColumn = () => () => undefined;
exports.User = User;
exports.Project = Project;
exports.SharedWorkflow = SharedWorkflow;
exports.SharedCredentials = SharedCredentials;
exports.WorkflowEntity = WorkflowEntity;
exports.GLOBAL_ADMIN_ROLE = GLOBAL_ADMIN_ROLE;
exports.GLOBAL_OWNER_ROLE = GLOBAL_OWNER_ROLE;
exports.GLOBAL_MEMBER_ROLE = GLOBAL_MEMBER_ROLE;
exports.WorkflowRepository = WorkflowRepository;
exports.UserRepository = UserRepository;
exports.SharedWorkflowRepository = SharedWorkflowRepository;
exports.ProjectRepository = ProjectRepository;
exports.CredentialsRepository = CredentialsRepository;
exports.WebhookRepository = WebhookRepository;
exports.withTransaction = withTransaction;
exports.WithTimestamps = WithTimestamps;
exports.WithSoftDelete = WithSoftDelete;
exports.JsonColumn = JsonColumn;
