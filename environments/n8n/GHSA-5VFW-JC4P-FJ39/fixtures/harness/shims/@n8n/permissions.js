"use strict";
// Adapter, not upstream code: the lab does not install n8n's own workspace
// packages. Only the exported names that the pinned modules touch at run time
// are implemented; decorator factories that only register providers are inert.
const PROJECT_VIEWER_ROLE_SLUG = "project:viewer";
const PROJECT_EDITOR_ROLE_SLUG = "project:editor";
const PROJECT_ADMIN_ROLE_SLUG = "project:admin";
const PROJECT_OWNER_ROLE_SLUG = "project:owner";
const BUILT_IN_ROLES = [PROJECT_VIEWER_ROLE_SLUG, PROJECT_EDITOR_ROLE_SLUG, PROJECT_ADMIN_ROLE_SLUG, PROJECT_OWNER_ROLE_SLUG];
const isBuiltInRole = (role) => BUILT_IN_ROLES.includes(role);
exports.PROJECT_VIEWER_ROLE_SLUG = PROJECT_VIEWER_ROLE_SLUG;
exports.PROJECT_EDITOR_ROLE_SLUG = PROJECT_EDITOR_ROLE_SLUG;
exports.PROJECT_ADMIN_ROLE_SLUG = PROJECT_ADMIN_ROLE_SLUG;
exports.PROJECT_OWNER_ROLE_SLUG = PROJECT_OWNER_ROLE_SLUG;
exports.isBuiltInRole = isBuiltInRole;
exports.hasGlobalScope = () => false;
