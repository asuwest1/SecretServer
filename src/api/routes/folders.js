import crypto from 'node:crypto';
import { json, readJson, sendError } from '../lib/http.js';
import { requireAuth, requireSuperAdmin } from '../services/security.js';

const MAX_FOLDER_DEPTH = 32;

function computeFolderDepth(store, parentFolderId) {
  if (!parentFolderId) return { ok: true, depth: 1 };

  let depth = 1;
  const seen = new Set();
  let cursor = parentFolderId;

  while (cursor) {
    if (seen.has(cursor)) {
      return { ok: false, error: 'Folder hierarchy cycle detected.' };
    }
    seen.add(cursor);

    const parent = store.folders.find((f) => f.id === cursor);
    if (!parent) {
      return { ok: false, error: 'Parent folder not found.' };
    }

    depth += 1;
    if (depth > MAX_FOLDER_DEPTH) {
      return { ok: false, error: `Folder depth exceeds maximum of ${MAX_FOLDER_DEPTH}.` };
    }

    cursor = parent.parentFolderId || null;
  }

  return { ok: true, depth };
}

export function registerFolderRoutes(router) {
  router.register('GET', /^\/api\/v1\/folders$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'read');
    if (!actor) return;

    if (actor.isSuperAdmin) {
      json(res, 200, { data: ctx.store.folders });
      return;
    }

    const roleIds = ctx.store.userRoles.filter((ur) => ur.userId === actor.id).map((ur) => ur.roleId);
    const allowedFolderIds = new Set(
      ctx.store.folderAcl.filter((f) => roleIds.includes(f.roleId) && f.canView).map((f) => f.folderId)
    );
    json(res, 200, { data: ctx.store.folders.filter((f) => allowedFolderIds.has(f.id)) });
  });

  router.register('POST', /^\/api\/v1\/folders$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const body = await readJson(req);
    if (!body.name) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Folder name is required.', ctx.traceId);
      return;
    }

    const parentFolderId = body.parentFolderId || null;
    const depthCheck = computeFolderDepth(ctx.store, parentFolderId);
    if (!depthCheck.ok) {
      sendError(res, 400, 'VALIDATION_ERROR', depthCheck.error, ctx.traceId);
      return;
    }

    const folder = {
      id: crypto.randomUUID(),
      name: body.name,
      parentFolderId,
      createdBy: actor.id,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    ctx.store.folders.push(folder);
    json(res, 201, { data: folder });
  });

  router.register('GET', /^\/api\/v1\/folders\/(?<id>[0-9a-f-]+)\/acl$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const folder = ctx.store.folders.find((f) => f.id === ctx.params.id);
    if (!folder) {
      sendError(res, 404, 'NOT_FOUND', 'Folder not found.', ctx.traceId);
      return;
    }

    const entries = ctx.store.folderAcl.filter((entry) => entry.folderId === folder.id);
    json(res, 200, { data: entries });
  });

  router.register('PUT', /^\/api\/v1\/folders\/(?<id>[0-9a-f-]+)\/acl$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const folder = ctx.store.folders.find((f) => f.id === ctx.params.id);
    if (!folder) {
      sendError(res, 404, 'NOT_FOUND', 'Folder not found.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    ctx.store.folderAcl = ctx.store.folderAcl.filter((f) => f.folderId !== ctx.params.id);
    for (const entry of body.entries || []) {
      ctx.store.folderAcl.push({
        folderId: ctx.params.id,
        roleId: entry.roleId,
        canAdd: !!entry.canAdd,
        canView: !!entry.canView,
        canChange: !!entry.canChange,
        canDelete: !!entry.canDelete,
      });
    }

    json(res, 200, { data: { ok: true } });
  });
}
