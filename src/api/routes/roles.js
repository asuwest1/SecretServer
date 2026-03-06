import crypto from 'node:crypto';
import { json, readJson, sendError } from '../lib/http.js';
import { requireAuth, requireSuperAdmin } from '../services/security.js';

export function registerRoleRoutes(router) {
  router.register('GET', /^\/api\/v1\/roles$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;
    json(res, 200, { data: ctx.store.roles });
  });

  router.register('POST', /^\/api\/v1\/roles$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;
    const body = await readJson(req);

    if (!body.name) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Role name is required.', ctx.traceId);
      return;
    }

    if (ctx.store.roles.some((r) => r.name === body.name)) {
      sendError(res, 409, 'CONFLICT', 'Role already exists.', ctx.traceId);
      return;
    }

    const role = {
      id: crypto.randomUUID(),
      name: body.name,
      description: body.description || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    ctx.store.roles.push(role);

    json(res, 201, { data: role });
  });

  router.register('POST', /^\/api\/v1\/roles\/(?<id>[0-9a-f-]+)\/members$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;
    const body = await readJson(req);

    const role = ctx.store.roles.find((r) => r.id === ctx.params.id);
    const user = ctx.store.users.find((u) => u.id === body.userId);
    if (!role || !user) {
      sendError(res, 404, 'NOT_FOUND', 'Role or user not found.', ctx.traceId);
      return;
    }

    if (!ctx.store.userRoles.some((ur) => ur.userId === user.id && ur.roleId === role.id)) {
      ctx.store.userRoles.push({
        userId: user.id,
        roleId: role.id,
        assignedAt: new Date().toISOString(),
        assignedBy: actor.id,
      });
    }

    json(res, 200, { data: { ok: true } });
  });
}

