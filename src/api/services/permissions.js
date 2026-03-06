function buildFolderLineage(folderId, folders) {
  if (!folderId || !Array.isArray(folders)) {
    return [folderId].filter(Boolean);
  }

  const byId = new Map(folders.map((folder) => [folder.id, folder]));
  const lineage = [];
  const seen = new Set();
  let current = folderId;

  while (current && !seen.has(current)) {
    seen.add(current);
    lineage.push(current);
    const folder = byId.get(current);
    current = folder?.parentFolderId || null;
  }

  return lineage;
}

export function resolveSecretPermission({
  user,
  roleIds,
  secretId,
  secretAcl,
  folderId,
  folderAcl,
  folders = [],
  permission,
}) {
  if (!user || !user.isActive) {
    return false;
  }
  if (user.isSuperAdmin) {
    return true;
  }

  const effectiveRoleIds = new Set(roleIds || []);
  const field = `can${permission.charAt(0).toUpperCase()}${permission.slice(1)}`;

  // Precedence rule: direct secret ACL overrides inherited folder ACL for that secret.
  const hasSecretOverrides = (secretAcl || []).some((entry) => entry.secretId === secretId);
  if (hasSecretOverrides) {
    return (secretAcl || []).some((entry) => (
      entry.secretId === secretId
      && effectiveRoleIds.has(entry.roleId)
      && entry[field] === true
    ));
  }

  const folderIds = new Set(buildFolderLineage(folderId, folders));
  return (folderAcl || []).some((entry) => (
    folderIds.has(entry.folderId)
    && effectiveRoleIds.has(entry.roleId)
    && entry[field] === true
  ));
}
