import crypto from 'node:crypto';
import { json, readJson, sendError } from '../lib/http.js';
import { requireAuth } from '../services/security.js';
import { resolveSecretPermission } from '../services/permissions.js';

function getRoleIds(store, userId) {
  return store.userRoles.filter((ur) => ur.userId === userId).map((ur) => ur.roleId);
}

function can(store, user, secret, permission) {
  return resolveSecretPermission({
    user,
    roleIds: getRoleIds(store, user.id),
    secretId: secret.id,
    secretAcl: store.secretAcl,
    folderId: secret.folderId,
    folderAcl: store.folderAcl,
    folders: store.folders,
    permission,
  });
}

export function registerSecretRoutes(router) {
  router.register('GET', /^\/api\/v1\/secrets$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'read');
    if (!actor) return;

    const q = (ctx.query.q || '').toLowerCase();
    const results = [];

    for (const secret of ctx.store.secrets.filter((s) => !s.isDeleted)) {
      if (!can(ctx.store, actor, secret, 'view')) {
        continue;
      }

      const metadataText = `${secret.name} ${secret.username || ''} ${secret.url || ''} ${(secret.tags || []).join(' ')}`.toLowerCase();
      if (!q || metadataText.includes(q)) {
        results.push({
          id: secret.id,
          folderId: secret.folderId,
          name: secret.name,
          secretType: secret.secretType,
          username: secret.username,
          url: secret.url,
          tags: secret.tags,
          updatedAt: secret.updatedAt,
        });
        continue;
      }

      if (!secret.notesEnc) {
        continue;
      }

      const notes = ctx.crypto.decryptSecret({
        valueEnc: secret.notesEnc,
        dekEnc: secret.dekEnc,
      });
      if (notes.toLowerCase().includes(q)) {
        results.push({
          id: secret.id,
          folderId: secret.folderId,
          name: secret.name,
          secretType: secret.secretType,
          username: secret.username,
          url: secret.url,
          tags: secret.tags,
          updatedAt: secret.updatedAt,
        });
      }
    }

    json(res, 200, { data: results });
  });

  router.register('POST', /^\/api\/v1\/secrets$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    const body = await readJson(req);
    const folder = ctx.store.folders.find((f) => f.id === body.folderId);
    if (!folder) {
      sendError(res, 404, 'NOT_FOUND', 'Folder not found.', ctx.traceId);
      return;
    }

    const pseudoSecret = { id: 'new', folderId: folder.id };
    if (!resolveSecretPermission({
      user: actor,
      roleIds: getRoleIds(ctx.store, actor.id),
      secretId: pseudoSecret.id,
      secretAcl: ctx.store.secretAcl,
      folderId: folder.id,
      folderAcl: ctx.store.folderAcl,
      folders: ctx.store.folders,
      permission: 'add',
    })) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Add permission required on folder.', ctx.traceId);
      return;
    }

    await ctx.store.runInTransaction(async () => {
      const valueEncryption = ctx.crypto.encryptSecret(body.value || '');
      const valueDek = ctx.crypto.unwrapDek(valueEncryption.encryptedDek);
      const notesEncryption = ctx.crypto.encryptWithKey(body.notes || '', valueDek);

      const secret = {
        id: crypto.randomUUID(),
        folderId: body.folderId,
        name: body.name,
        secretType: body.secretType || 'password',
        username: body.username || null,
        url: body.url || null,
        tags: body.tags || [],
        valueEnc: valueEncryption.encryptedValue,
        notesEnc: notesEncryption,
        dekEnc: valueEncryption.encryptedDek,
        isDeleted: false,
        deletedAt: null,
        purgeAfter: null,
        createdBy: actor.id,
        createdAt: new Date().toISOString(),
        updatedBy: actor.id,
        updatedAt: new Date().toISOString(),
      };

      ctx.store.secrets.push(secret);
      ctx.store.appendAudit({
        userId: actor.id,
        username: actor.username,
        action: 'SECRET_CREATED',
        resource: 'secret',
        resourceId: secret.id,
        secretName: secret.name,
        ipAddress: req.socket.remoteAddress,
      });

      json(res, 201, { data: { id: secret.id } });
    });
  });

  router.register('GET', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)\/value$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'read');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id && !s.isDeleted);
    if (!secret) {
      sendError(res, 404, 'NOT_FOUND', 'Secret not found.', ctx.traceId);
      return;
    }

    if (!can(ctx.store, actor, secret, 'view')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'View permission required.', ctx.traceId);
      return;
    }

    await ctx.store.runInTransaction(async () => {
      const value = ctx.crypto.decryptSecret({
        valueEnc: secret.valueEnc,
        dekEnc: secret.dekEnc,
      });

      ctx.store.appendAudit({
        userId: actor.id,
        username: actor.username,
        action: 'SECRET_VIEWED',
        resource: 'secret',
        resourceId: secret.id,
        secretName: secret.name,
        ipAddress: req.socket.remoteAddress,
      });

      json(res, 200, { data: { value } });
    });
  });

  router.register('PUT', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id && !s.isDeleted);
    if (!secret) {
      sendError(res, 404, 'NOT_FOUND', 'Secret not found.', ctx.traceId);
      return;
    }

    if (!can(ctx.store, actor, secret, 'change')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Change permission required.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    await ctx.store.runInTransaction(async () => {
      const oldValue = secret.valueEnc;
      const oldDek = secret.dekEnc;

      if (body.value !== undefined) {
        const encrypted = ctx.crypto.encryptSecret(body.value);
        secret.valueEnc = encrypted.encryptedValue;
        secret.dekEnc = encrypted.encryptedDek;
      }
      if (body.notes !== undefined) {
        const secretDek = ctx.crypto.unwrapDek(secret.dekEnc);
        secret.notesEnc = ctx.crypto.encryptWithKey(body.notes, secretDek);
      }

      secret.name = body.name || secret.name;
      secret.username = body.username ?? secret.username;
      secret.url = body.url ?? secret.url;
      secret.tags = body.tags || secret.tags;
      secret.updatedBy = actor.id;
      secret.updatedAt = new Date().toISOString();

      ctx.store.secretVersions.push({
        id: crypto.randomUUID(),
        secretId: secret.id,
        versionNum: ctx.store.secretVersions.filter((v) => v.secretId === secret.id).length + 1,
        valueEnc: oldValue,
        dekEnc: oldDek,
        changedBy: actor.id,
        changedAt: new Date().toISOString(),
      });

      ctx.store.appendAudit({
        userId: actor.id,
        username: actor.username,
        action: 'SECRET_UPDATED',
        resource: 'secret',
        resourceId: secret.id,
        secretName: secret.name,
        ipAddress: req.socket.remoteAddress,
      });

      json(res, 200, { data: { ok: true } });
    });
  });

  router.register('DELETE', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id && !s.isDeleted);
    if (!secret) {
      sendError(res, 404, 'NOT_FOUND', 'Secret not found.', ctx.traceId);
      return;
    }

    if (!can(ctx.store, actor, secret, 'delete')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Delete permission required.', ctx.traceId);
      return;
    }

    await ctx.store.runInTransaction(async () => {
      secret.isDeleted = true;
      secret.deletedAt = new Date().toISOString();
      secret.purgeAfter = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();

      ctx.store.appendAudit({
        userId: actor.id,
        username: actor.username,
        action: 'SECRET_DELETED',
        resource: 'secret',
        resourceId: secret.id,
        secretName: secret.name,
        ipAddress: req.socket.remoteAddress,
      });

      json(res, 200, { data: { ok: true } });
    });
  });

  router.register('POST', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)\/restore$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id && s.isDeleted);
    if (!secret) {
      sendError(res, 404, 'NOT_FOUND', 'Secret not found.', ctx.traceId);
      return;
    }

    if (!can(ctx.store, actor, secret, 'change')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Change permission required.', ctx.traceId);
      return;
    }

    await ctx.store.runInTransaction(async () => {
      secret.isDeleted = false;
      secret.deletedAt = null;
      secret.purgeAfter = null;

      ctx.store.appendAudit({
        userId: actor.id,
        username: actor.username,
        action: 'SECRET_RESTORED',
        resource: 'secret',
        resourceId: secret.id,
        secretName: secret.name,
        ipAddress: req.socket.remoteAddress,
      });

      json(res, 200, { data: { ok: true } });
    });
  });

  router.register('GET', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)\/versions$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'read');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id);
    if (!secret || !can(ctx.store, actor, secret, 'change')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Change permission required.', ctx.traceId);
      return;
    }

    const versions = ctx.store.secretVersions.filter((v) => v.secretId === secret.id);
    json(res, 200, { data: versions });
  });

  router.register('GET', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)\/acl$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'read');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id);
    if (!secret) {
      sendError(res, 404, 'NOT_FOUND', 'Secret not found.', ctx.traceId);
      return;
    }

    if (!can(ctx.store, actor, secret, 'change')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Change permission required.', ctx.traceId);
      return;
    }

    const entries = ctx.store.secretAcl.filter((entry) => entry.secretId === secret.id);
    json(res, 200, { data: entries });
  });

  router.register('PUT', /^\/api\/v1\/secrets\/(?<id>[0-9a-f-]+)\/acl$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    const secret = ctx.store.secrets.find((s) => s.id === ctx.params.id);
    if (!secret) {
      sendError(res, 404, 'NOT_FOUND', 'Secret not found.', ctx.traceId);
      return;
    }

    if (!can(ctx.store, actor, secret, 'change')) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Change permission required.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    await ctx.store.runInTransaction(async () => {
      ctx.store.secretAcl = ctx.store.secretAcl.filter((a) => a.secretId !== secret.id);
      for (const entry of body.entries || []) {
        ctx.store.secretAcl.push({
          secretId: secret.id,
          roleId: entry.roleId,
          canAdd: !!entry.canAdd,
          canView: !!entry.canView,
          canChange: !!entry.canChange,
          canDelete: !!entry.canDelete,
        });
      }

      ctx.store.appendAudit({
        userId: actor.id,
        username: actor.username,
        action: 'SECRET_ACL_UPDATED',
        resource: 'secret',
        resourceId: secret.id,
        secretName: secret.name,
        ipAddress: req.socket.remoteAddress,
      });

      json(res, 200, { data: { ok: true } });
    });
  });
}


