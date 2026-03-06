import React from 'react';
import { useEffect, useMemo, useState } from 'react';
import { apiRequest, decodeJwtPayload } from './api.js';

function emptySecretDraft(folderId = '') {
  return {
    folderId,
    name: '',
    value: '',
    notes: '',
    username: '',
    url: '',
    tags: '',
  };
}

function emptyUserDraft() {
  return {
    username: '',
    password: '',
    displayName: '',
    email: '',
    isSuperAdmin: false,
  };
}

function createAclEntries(roles) {
  return roles.map((role) => ({
    roleId: role.id,
    roleName: role.name,
    canAdd: false,
    canView: false,
    canChange: false,
    canDelete: false,
  }));
}

function toAclPayload(entries) {
  return entries
    .filter((entry) => entry.canAdd || entry.canView || entry.canChange || entry.canDelete)
    .map(({ roleId, canAdd, canView, canChange, canDelete }) => ({
      roleId,
      canAdd,
      canView,
      canChange,
      canDelete,
    }));
}

function buildAclEntriesFromExisting(roles, existing) {
  const byRole = new Map((existing || []).map((entry) => [entry.roleId, entry]));
  return roles.map((role) => {
    const saved = byRole.get(role.id);
    return {
      roleId: role.id,
      roleName: role.name,
      canAdd: Boolean(saved?.canAdd),
      canView: Boolean(saved?.canView),
      canChange: Boolean(saved?.canChange),
      canDelete: Boolean(saved?.canDelete),
    };
  });
}

export default function App() {
  const [health, setHealth] = useState('loading');
  const [token, setToken] = useState(() => localStorage.getItem('ss_access_token') || '');
  const [activeView, setActiveView] = useState('vault');
  const [error, setError] = useState('');

  const [vaultLoading, setVaultLoading] = useState(false);
  const [adminLoading, setAdminLoading] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);
  const [versionsLoading, setVersionsLoading] = useState(false);

  const [loginForm, setLoginForm] = useState({ username: 'superadmin', password: 'ChangeMeNow!123' });

  const [folders, setFolders] = useState([]);
  const [secrets, setSecrets] = useState([]);
  const [query, setQuery] = useState('');
  const [selectedSecretId, setSelectedSecretId] = useState('');
  const [revealedValue, setRevealedValue] = useState('');
  const [secretDraft, setSecretDraft] = useState(emptySecretDraft());
  const [secretVersions, setSecretVersions] = useState([]);

  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [userDraft, setUserDraft] = useState(emptyUserDraft());
  const [roleDraft, setRoleDraft] = useState({ name: '', description: '' });
  const [assignment, setAssignment] = useState({ userId: '', roleId: '' });
  const [tokenIssue, setTokenIssue] = useState({ userId: '', scope: 'read' });
  const [issuedApiToken, setIssuedApiToken] = useState('');

  const [folderAclTargetId, setFolderAclTargetId] = useState('');
  const [folderAclEntries, setFolderAclEntries] = useState([]);
  const [secretAclTargetId, setSecretAclTargetId] = useState('');
  const [secretAclEntries, setSecretAclEntries] = useState([]);

  const [auditRows, setAuditRows] = useState([]);
  const [auditFilters, setAuditFilters] = useState({ from: '', to: '' });
  const [auditExportPreview, setAuditExportPreview] = useState('');

  const claims = useMemo(() => decodeJwtPayload(token), [token]);
  const isAuthed = Boolean(token);
  const isSuperAdmin = Boolean(claims?.isSuperAdmin);

  useEffect(() => {
    apiRequest('/health')
      .then((data) => setHealth(data?.status || 'down'))
      .catch(() => setHealth('down'));
  }, []);

  useEffect(() => {
    if (token) {
      localStorage.setItem('ss_access_token', token);
      setError('');
      loadVault();
      if (isSuperAdmin) {
        loadAdmin();
        loadAudit();
      }
    } else {
      localStorage.removeItem('ss_access_token');
      setFolders([]);
      setSecrets([]);
      setUsers([]);
      setRoles([]);
      setAuditRows([]);
      setSecretVersions([]);
      setSelectedSecretId('');
      setRevealedValue('');
    }
  }, [token]);

  useEffect(() => {
    setFolderAclTargetId((current) => current || folders[0]?.id || '');
    setSecretAclTargetId((current) => current || secrets[0]?.id || '');
  }, [folders, secrets]);

  useEffect(() => {
    if (!isAuthed || !isSuperAdmin || !folderAclTargetId || roles.length === 0) {
      setFolderAclEntries(createAclEntries(roles));
      return;
    }

    let cancelled = false;
    guarded(async () => {
      const data = await apiRequest(`/api/v1/folders/${folderAclTargetId}/acl`, { token });
      if (!cancelled) {
        setFolderAclEntries(buildAclEntriesFromExisting(roles, data));
      }
    });

    return () => {
      cancelled = true;
    };
  }, [isAuthed, isSuperAdmin, folderAclTargetId, roles, token]);

  useEffect(() => {
    if (!isAuthed || !secretAclTargetId || roles.length === 0) {
      setSecretAclEntries(createAclEntries(roles));
      return;
    }

    let cancelled = false;
    guarded(async () => {
      const data = await apiRequest(`/api/v1/secrets/${secretAclTargetId}/acl`, { token });
      if (!cancelled) {
        setSecretAclEntries(buildAclEntriesFromExisting(roles, data));
      }
    });

    return () => {
      cancelled = true;
    };
  }, [isAuthed, secretAclTargetId, roles, token]);

  async function guarded(action) {
    try {
      setError('');
      await action();
    } catch (err) {
      setError(err.message || 'Unexpected error');
      if (err.status === 401) {
        setToken('');
      }
    }
  }

  async function login(e) {
    e.preventDefault();
    await guarded(async () => {
      const data = await apiRequest('/api/v1/auth/login', {
        method: 'POST',
        body: {
          username: loginForm.username,
          password: loginForm.password,
        },
      });
      if (!data?.accessToken) {
        throw new Error('Login succeeded but no access token was returned.');
      }
      setToken(data.accessToken);
    });
  }

  function logout() {
    setToken('');
  }

  function setAclPermission(setter, roleId, field, value) {
    setter((prev) => prev.map((entry) => (entry.roleId === roleId ? { ...entry, [field]: value } : entry)));
  }

  async function loadVault() {
    await guarded(async () => {
      setVaultLoading(true);
      const [folderData, secretData] = await Promise.all([
        apiRequest('/api/v1/folders', { token }),
        apiRequest(`/api/v1/secrets${query ? `?q=${encodeURIComponent(query)}` : ''}`, { token }),
      ]);
      setFolders(folderData || []);
      setSecrets(secretData || []);
      setSecretDraft((prev) => ({ ...prev, folderId: prev.folderId || folderData?.[0]?.id || '' }));
      setFolderAclTargetId((current) => current || folderData?.[0]?.id || '');
      setSecretAclTargetId((current) => current || secretData?.[0]?.id || '');
    });
    setVaultLoading(false);
  }

  async function revealSecret(secretId) {
    await guarded(async () => {
      const data = await apiRequest(`/api/v1/secrets/${secretId}/value`, { token });
      setSelectedSecretId(secretId);
      setRevealedValue(data?.value || '');
    });
  }

  async function loadSecretVersions(secretId) {
    if (!secretId) return;
    await guarded(async () => {
      setVersionsLoading(true);
      const data = await apiRequest(`/api/v1/secrets/${secretId}/versions`, { token });
      setSelectedSecretId(secretId);
      setSecretVersions(data || []);
    });
    setVersionsLoading(false);
  }

  async function createSecret(e) {
    e.preventDefault();
    await guarded(async () => {
      await apiRequest('/api/v1/secrets', {
        method: 'POST',
        token,
        body: {
          folderId: secretDraft.folderId,
          name: secretDraft.name,
          value: secretDraft.value,
          notes: secretDraft.notes,
          username: secretDraft.username || null,
          url: secretDraft.url || null,
          tags: secretDraft.tags.split(',').map((x) => x.trim()).filter(Boolean),
        },
      });
      setSecretDraft(emptySecretDraft(secretDraft.folderId));
      await loadVault();
    });
  }

  async function loadAdmin() {
    await guarded(async () => {
      setAdminLoading(true);
      const [userData, roleData] = await Promise.all([
        apiRequest('/api/v1/users', { token }),
        apiRequest('/api/v1/roles', { token }),
      ]);
      setUsers(userData || []);
      setRoles(roleData || []);
      setAssignment((prev) => ({
        userId: prev.userId || userData?.[0]?.id || '',
        roleId: prev.roleId || roleData?.[0]?.id || '',
      }));
      setTokenIssue((prev) => ({ userId: prev.userId || userData?.[0]?.id || '', scope: prev.scope || 'read' }));
    });
    setAdminLoading(false);
  }

  async function createUser(e) {
    e.preventDefault();
    await guarded(async () => {
      await apiRequest('/api/v1/users', {
        method: 'POST',
        token,
        body: userDraft,
      });
      setUserDraft(emptyUserDraft());
      await loadAdmin();
    });
  }

  async function createRole(e) {
    e.preventDefault();
    await guarded(async () => {
      await apiRequest('/api/v1/roles', {
        method: 'POST',
        token,
        body: roleDraft,
      });
      setRoleDraft({ name: '', description: '' });
      await loadAdmin();
    });
  }

  async function assignRole(e) {
    e.preventDefault();
    await guarded(async () => {
      await apiRequest(`/api/v1/roles/${assignment.roleId}/members`, {
        method: 'POST',
        token,
        body: { userId: assignment.userId },
      });
      await loadAdmin();
    });
  }

  async function issueApiToken(e) {
    e.preventDefault();
    await guarded(async () => {
      const data = await apiRequest(`/api/v1/users/${tokenIssue.userId}/api-tokens`, {
        method: 'POST',
        token,
        body: {
          name: `ui-${tokenIssue.scope}`,
          scopes: [tokenIssue.scope],
        },
      });
      setIssuedApiToken(data?.rawToken || '');
    });
  }

  async function updateFolderAcl(e) {
    e.preventDefault();
    if (!folderAclTargetId) return;
    await guarded(async () => {
      await apiRequest(`/api/v1/folders/${folderAclTargetId}/acl`, {
        method: 'PUT',
        token,
        body: { entries: toAclPayload(folderAclEntries) },
      });
      const refreshed = await apiRequest(`/api/v1/folders/${folderAclTargetId}/acl`, { token });
      setFolderAclEntries(buildAclEntriesFromExisting(roles, refreshed));
    });
  }

  async function updateSecretAcl(e) {
    e.preventDefault();
    if (!secretAclTargetId) return;
    await guarded(async () => {
      await apiRequest(`/api/v1/secrets/${secretAclTargetId}/acl`, {
        method: 'PUT',
        token,
        body: { entries: toAclPayload(secretAclEntries) },
      });
      const refreshed = await apiRequest(`/api/v1/secrets/${secretAclTargetId}/acl`, { token });
      setSecretAclEntries(buildAclEntriesFromExisting(roles, refreshed));
    });
  }

  async function loadAudit() {
    await guarded(async () => {
      setAuditLoading(true);
      const params = new URLSearchParams();
      if (auditFilters.from) params.set('from', auditFilters.from);
      if (auditFilters.to) params.set('to', auditFilters.to);
      const queryString = params.toString();
      const data = await apiRequest(`/api/v1/audit${queryString ? `?${queryString}` : ''}`, { token });
      setAuditRows(data || []);
    });
    setAuditLoading(false);
  }

  async function exportAudit(format) {
    await guarded(async () => {
      if (format === 'json') {
        const data = await apiRequest('/api/v1/audit/export?format=json', { token });
        setAuditExportPreview(JSON.stringify(data || [], null, 2));
        return;
      }

      const response = await fetch('/api/v1/audit/export?format=csv', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (!response.ok) {
        throw new Error(`CSV export failed with status ${response.status}`);
      }
      const csv = await response.text();
      setAuditExportPreview(csv);
    });
  }

  return (
    <div className="app">
      <div className="shell">
        <header className="topbar">
          <div>
            <h1 className="title">Secret Server Console</h1>
            <div className="status">
              <span className="pill">API: <strong className={health === 'ok' ? 'good' : 'bad'}>{health}</strong></span>
              <span className="pill">Auth: <strong>{isAuthed ? 'active' : 'signed-out'}</strong></span>
              {claims?.username ? <span className="pill">User: {claims.username}</span> : null}
            </div>
          </div>
          <div className="row">
            {isAuthed ? <button onClick={logout}>Logout</button> : null}
            <button onClick={loadVault} disabled={!isAuthed || vaultLoading}>Refresh Vault</button>
            <button onClick={loadAdmin} disabled={!isAuthed || !isSuperAdmin || adminLoading}>Refresh Admin</button>
            <button onClick={loadAudit} disabled={!isAuthed || !isSuperAdmin || auditLoading}>Refresh Audit</button>
          </div>
        </header>

        {!isAuthed ? (
          <section className="content">
            <div className="card span-12" style={{ maxWidth: 460 }}>
              <h3>Login</h3>
              <form onSubmit={login}>
                <div className="row">
                  <input
                    value={loginForm.username}
                    onChange={(e) => setLoginForm((f) => ({ ...f, username: e.target.value }))}
                    placeholder="Username"
                  />
                </div>
                <div className="row">
                  <input
                    type="password"
                    value={loginForm.password}
                    onChange={(e) => setLoginForm((f) => ({ ...f, password: e.target.value }))}
                    placeholder="Password"
                  />
                </div>
                <button className="primary" type="submit">Sign In</button>
              </form>
              <p className="muted">Default bootstrap credentials are prefilled for local development only.</p>
            </div>
            {error ? <p className="error">{error}</p> : null}
          </section>
        ) : (
          <div className="main">
            <aside className="nav">
              <button className={activeView === 'vault' ? 'active' : ''} onClick={() => setActiveView('vault')}>Vault</button>
              <button className={activeView === 'admin' ? 'active' : ''} onClick={() => setActiveView('admin')} disabled={!isSuperAdmin}>Admin</button>
              <button className={activeView === 'audit' ? 'active' : ''} onClick={() => setActiveView('audit')} disabled={!isSuperAdmin}>Audit</button>
            </aside>

            <section className="content">
              {error ? <p className="error">{error}</p> : null}

              {activeView === 'vault' ? (
                <div className="grid">
                  <article className="card span-8">
                    <h3>Secrets</h3>
                    <div className="row">
                      <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name/url/tags/notes" />
                      <button onClick={loadVault} disabled={vaultLoading}>Search</button>
                    </div>
                    {vaultLoading ? <p className="muted">Loading vault data...</p> : null}
                    <table>
                      <thead>
                        <tr><th>Name</th><th>Folder</th><th>Type</th><th>Actions</th></tr>
                      </thead>
                      <tbody>
                        {secrets.map((s) => (
                          <tr key={s.id}>
                            <td>{s.name}</td>
                            <td>{folders.find((f) => f.id === s.folderId)?.name || s.folderId}</td>
                            <td>{s.secretType}</td>
                            <td className="row compact-row">
                              <button onClick={() => revealSecret(s.id)}>Reveal</button>
                              <button onClick={() => loadSecretVersions(s.id)}>Versions</button>
                              <button onClick={() => setSecretAclTargetId(s.id)}>Set ACL</button>
                            </td>
                          </tr>
                        ))}
                        {secrets.length === 0 ? <tr><td colSpan="4" className="muted">No visible secrets.</td></tr> : null}
                      </tbody>
                    </table>
                  </article>

                  <article className="card span-4">
                    <h3>Reveal</h3>
                    <p className="muted">Secret ID: {selectedSecretId || '(none selected)'}</p>
                    <div className="code">{revealedValue || 'Use Reveal on a secret row.'}</div>
                  </article>

                  <article className="card span-6">
                    <h3>Versions</h3>
                    {versionsLoading ? <p className="muted">Loading versions...</p> : null}
                    {!versionsLoading && secretVersions.length === 0 ? <p className="muted">No loaded versions. Click Versions on a secret.</p> : null}
                    <table>
                      <thead><tr><th>Version</th><th>Changed By</th><th>Changed At</th></tr></thead>
                      <tbody>
                        {secretVersions.map((version) => (
                          <tr key={version.id}>
                            <td>{version.versionNum}</td>
                            <td>{version.changedBy}</td>
                            <td>{version.changedAt}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </article>

                  <article className="card span-6">
                    <h3>Secret ACL</h3>
                    <form onSubmit={updateSecretAcl}>
                      <div className="row">
                        <select value={secretAclTargetId} onChange={(e) => setSecretAclTargetId(e.target.value)}>
                          <option value="">Select secret</option>
                          {secrets.map((secret) => <option key={secret.id} value={secret.id}>{secret.name}</option>)}
                        </select>
                        <button type="submit" disabled={!secretAclTargetId || roles.length === 0}>Apply Secret ACL</button>
                      </div>
                      {roles.length === 0 ? <p className="muted">Create roles before assigning ACL.</p> : null}
                      <table>
                        <thead><tr><th>Role</th><th>Add</th><th>View</th><th>Change</th><th>Delete</th></tr></thead>
                        <tbody>
                          {secretAclEntries.map((entry) => (
                            <tr key={entry.roleId}>
                              <td>{entry.roleName}</td>
                              <td><input type="checkbox" checked={entry.canAdd} onChange={(e) => setAclPermission(setSecretAclEntries, entry.roleId, 'canAdd', e.target.checked)} /></td>
                              <td><input type="checkbox" checked={entry.canView} onChange={(e) => setAclPermission(setSecretAclEntries, entry.roleId, 'canView', e.target.checked)} /></td>
                              <td><input type="checkbox" checked={entry.canChange} onChange={(e) => setAclPermission(setSecretAclEntries, entry.roleId, 'canChange', e.target.checked)} /></td>
                              <td><input type="checkbox" checked={entry.canDelete} onChange={(e) => setAclPermission(setSecretAclEntries, entry.roleId, 'canDelete', e.target.checked)} /></td>
                            </tr>
                          ))}
                          {secretAclEntries.length === 0 ? <tr><td colSpan="5" className="muted">No roles available for ACL mapping.</td></tr> : null}
                        </tbody>
                      </table>
                    </form>
                  </article>

                  <article className="card span-6">
                    <h3>Folder ACL</h3>
                    <form onSubmit={updateFolderAcl}>
                      <div className="row">
                        <select value={folderAclTargetId} onChange={(e) => setFolderAclTargetId(e.target.value)}>
                          <option value="">Select folder</option>
                          {folders.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}
                        </select>
                        <button type="submit" disabled={!folderAclTargetId || roles.length === 0}>Apply Folder ACL</button>
                      </div>
                      {folders.length === 0 ? <p className="muted">No folders available.</p> : null}
                      <table>
                        <thead><tr><th>Role</th><th>Add</th><th>View</th><th>Change</th><th>Delete</th></tr></thead>
                        <tbody>
                          {folderAclEntries.map((entry) => (
                            <tr key={entry.roleId}>
                              <td>{entry.roleName}</td>
                              <td><input type="checkbox" checked={entry.canAdd} onChange={(e) => setAclPermission(setFolderAclEntries, entry.roleId, 'canAdd', e.target.checked)} /></td>
                              <td><input type="checkbox" checked={entry.canView} onChange={(e) => setAclPermission(setFolderAclEntries, entry.roleId, 'canView', e.target.checked)} /></td>
                              <td><input type="checkbox" checked={entry.canChange} onChange={(e) => setAclPermission(setFolderAclEntries, entry.roleId, 'canChange', e.target.checked)} /></td>
                              <td><input type="checkbox" checked={entry.canDelete} onChange={(e) => setAclPermission(setFolderAclEntries, entry.roleId, 'canDelete', e.target.checked)} /></td>
                            </tr>
                          ))}
                          {folderAclEntries.length === 0 ? <tr><td colSpan="5" className="muted">No roles available for ACL mapping.</td></tr> : null}
                        </tbody>
                      </table>
                    </form>
                  </article>

                  <article className="card span-12">
                    <h3>Create Secret</h3>
                    <form onSubmit={createSecret}>
                      <div className="row">
                        <select value={secretDraft.folderId} onChange={(e) => setSecretDraft((d) => ({ ...d, folderId: e.target.value }))}>
                          <option value="">Select folder</option>
                          {folders.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
                        </select>
                        <input value={secretDraft.name} onChange={(e) => setSecretDraft((d) => ({ ...d, name: e.target.value }))} placeholder="Secret name" />
                        <input value={secretDraft.username} onChange={(e) => setSecretDraft((d) => ({ ...d, username: e.target.value }))} placeholder="Username" />
                        <input value={secretDraft.url} onChange={(e) => setSecretDraft((d) => ({ ...d, url: e.target.value }))} placeholder="URL" />
                      </div>
                      <div className="row">
                        <input value={secretDraft.tags} onChange={(e) => setSecretDraft((d) => ({ ...d, tags: e.target.value }))} placeholder="Tags (comma-separated)" />
                        <input type="password" value={secretDraft.value} onChange={(e) => setSecretDraft((d) => ({ ...d, value: e.target.value }))} placeholder="Secret value" />
                      </div>
                      <textarea value={secretDraft.notes} onChange={(e) => setSecretDraft((d) => ({ ...d, notes: e.target.value }))} placeholder="Notes" />
                      <div className="row">
                        <button className="primary" type="submit" disabled={!secretDraft.folderId || !secretDraft.name || !secretDraft.value}>Create Secret</button>
                      </div>
                    </form>
                  </article>
                </div>
              ) : null}

              {activeView === 'admin' ? (
                <div className="grid">
                  <article className="card span-6">
                    <h3>Create User</h3>
                    {adminLoading ? <p className="muted">Loading admin data...</p> : null}
                    <form onSubmit={createUser}>
                      <div className="row">
                        <input value={userDraft.username} onChange={(e) => setUserDraft((d) => ({ ...d, username: e.target.value }))} placeholder="Username" />
                        <input value={userDraft.displayName} onChange={(e) => setUserDraft((d) => ({ ...d, displayName: e.target.value }))} placeholder="Display name" />
                      </div>
                      <div className="row">
                        <input value={userDraft.email} onChange={(e) => setUserDraft((d) => ({ ...d, email: e.target.value }))} placeholder="Email" />
                        <input type="password" value={userDraft.password} onChange={(e) => setUserDraft((d) => ({ ...d, password: e.target.value }))} placeholder="Password" />
                      </div>
                      <div className="row">
                        <label>
                          <input type="checkbox" checked={userDraft.isSuperAdmin} onChange={(e) => setUserDraft((d) => ({ ...d, isSuperAdmin: e.target.checked }))} /> Super Admin
                        </label>
                      </div>
                      <button className="primary" type="submit">Create User</button>
                    </form>
                  </article>

                  <article className="card span-6">
                    <h3>Create Role</h3>
                    <form onSubmit={createRole}>
                      <div className="row">
                        <input value={roleDraft.name} onChange={(e) => setRoleDraft((d) => ({ ...d, name: e.target.value }))} placeholder="Role name" />
                        <input value={roleDraft.description} onChange={(e) => setRoleDraft((d) => ({ ...d, description: e.target.value }))} placeholder="Description" />
                      </div>
                      <button className="primary" type="submit">Create Role</button>
                    </form>

                    <h3 style={{ marginTop: 16 }}>Assign Role</h3>
                    <form onSubmit={assignRole}>
                      <div className="row">
                        <select value={assignment.userId} onChange={(e) => setAssignment((a) => ({ ...a, userId: e.target.value }))}>
                          {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                        </select>
                        <select value={assignment.roleId} onChange={(e) => setAssignment((a) => ({ ...a, roleId: e.target.value }))}>
                          {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                        </select>
                        <button type="submit" disabled={users.length === 0 || roles.length === 0}>Assign</button>
                      </div>
                    </form>
                  </article>

                  <article className="card span-6">
                    <h3>Issue API Token</h3>
                    <form onSubmit={issueApiToken}>
                      <div className="row">
                        <select value={tokenIssue.userId} onChange={(e) => setTokenIssue((s) => ({ ...s, userId: e.target.value }))}>
                          {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                        </select>
                        <select value={tokenIssue.scope} onChange={(e) => setTokenIssue((s) => ({ ...s, scope: e.target.value }))}>
                          <option value="read">read</option>
                          <option value="write">write</option>
                          <option value="admin">admin</option>
                        </select>
                        <button type="submit" disabled={users.length === 0}>Issue</button>
                      </div>
                    </form>
                    <div className="code">{issuedApiToken || 'Issued raw token will appear here once.'}</div>
                  </article>

                  <article className="card span-6">
                    <h3>Users</h3>
                    <table>
                      <thead><tr><th>Username</th><th>Email</th><th>Super</th><th>Active</th></tr></thead>
                      <tbody>
                        {users.map((u) => (
                          <tr key={u.id}><td>{u.username}</td><td>{u.email}</td><td>{String(u.isSuperAdmin)}</td><td>{String(u.isActive)}</td></tr>
                        ))}
                        {users.length === 0 ? <tr><td colSpan="4" className="muted">No users found.</td></tr> : null}
                      </tbody>
                    </table>
                  </article>

                  <article className="card span-12">
                    <h3>Roles</h3>
                    <table>
                      <thead><tr><th>Name</th><th>Description</th><th>ID</th></tr></thead>
                      <tbody>
                        {roles.map((r) => (
                          <tr key={r.id}><td>{r.name}</td><td>{r.description}</td><td className="code">{r.id}</td></tr>
                        ))}
                        {roles.length === 0 ? <tr><td colSpan="3" className="muted">No roles found.</td></tr> : null}
                      </tbody>
                    </table>
                  </article>
                </div>
              ) : null}

              {activeView === 'audit' ? (
                <div className="grid">
                  <article className="card span-12">
                    <h3>Audit Query</h3>
                    <div className="row">
                      <label>
                        From:
                        <input
                          type="datetime-local"
                          value={auditFilters.from}
                          onChange={(e) => setAuditFilters((prev) => ({ ...prev, from: e.target.value }))}
                        />
                      </label>
                      <label>
                        To:
                        <input
                          type="datetime-local"
                          value={auditFilters.to}
                          onChange={(e) => setAuditFilters((prev) => ({ ...prev, to: e.target.value }))}
                        />
                      </label>
                      <button onClick={loadAudit} disabled={auditLoading}>Run Query</button>
                      <button onClick={() => exportAudit('json')}>Export JSON</button>
                      <button onClick={() => exportAudit('csv')}>Export CSV</button>
                    </div>
                    {auditLoading ? <p className="muted">Loading audit records...</p> : null}
                    <table>
                      <thead><tr><th>Time</th><th>Action</th><th>User</th><th>Resource</th><th>Resource ID</th></tr></thead>
                      <tbody>
                        {auditRows.map((row) => (
                          <tr key={row.id}>
                            <td>{row.eventTime}</td>
                            <td>{row.action}</td>
                            <td>{row.username}</td>
                            <td>{row.resource}</td>
                            <td className="code">{row.resourceId}</td>
                          </tr>
                        ))}
                        {auditRows.length === 0 ? <tr><td colSpan="5" className="muted">No audit events in selected range.</td></tr> : null}
                      </tbody>
                    </table>
                  </article>

                  <article className="card span-12">
                    <h3>Audit Export Preview</h3>
                    <div className="code export-preview">{auditExportPreview || 'Run an export to preview payload.'}</div>
                  </article>
                </div>
              ) : null}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}





