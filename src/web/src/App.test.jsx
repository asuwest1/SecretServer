import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App.jsx';
import { apiRequest, decodeJwtPayload } from './api.js';

vi.mock('./api.js', () => ({
  apiRequest: vi.fn(),
  decodeJwtPayload: vi.fn(),
}));

beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
  decodeJwtPayload.mockImplementation((token) => (token ? { username: 'superadmin', isSuperAdmin: true } : null));
  global.fetch = vi.fn(async () => ({
    ok: true,
    text: async () => 'id,eventTime\n',
  }));
});

afterEach(() => {
  vi.restoreAllMocks();
});

function installDefaultApiMock() {
  apiRequest.mockImplementation(async (path) => {
    if (path === '/health') return { status: 'ok' };
    if (path === '/api/v1/auth/login') return { accessToken: 'token-1' };
    if (path === '/api/v1/folders') return [{ id: 'f1', name: 'Ops' }];
    if (path === '/api/v1/secrets') return [{ id: 's1', folderId: 'f1', name: 'DB Password', secretType: 'password' }];
    if (path === '/api/v1/secrets/s1/value') return { value: 'top-secret' };
    if (path === '/api/v1/secrets/s1/versions') return [{ id: 'v1', versionNum: 1, changedBy: 'u1', changedAt: '2026-01-01T00:00:00Z' }];
    if (path === '/api/v1/users') return [{ id: 'u1', username: 'superadmin', email: 'sa@test', isSuperAdmin: true, isActive: true }];
    if (path === '/api/v1/roles') return [{ id: 'r1', name: 'Admins', description: 'admin role' }];
    if (path.includes('/acl')) return [];
    if (path.startsWith('/api/v1/audit')) return [];
    return { ok: true };
  });
}

it('renders the login form when not authenticated', async () => {
  apiRequest.mockResolvedValueOnce({ status: 'ok' });

  render(<App />);

  expect(await screen.findByRole('heading', { name: 'Login' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument();
});

it('logs in, reveals a secret, and loads versions', async () => {
  installDefaultApiMock();

  render(<App />);

  await userEvent.click(await screen.findByRole('button', { name: 'Sign In' }));
  expect(await screen.findByRole('button', { name: 'Logout' })).toBeInTheDocument();
  expect(await screen.findByRole('button', { name: 'Reveal' })).toBeInTheDocument();

  await userEvent.click(screen.getByRole('button', { name: 'Reveal' }));
  await userEvent.click(screen.getByRole('button', { name: 'Versions' }));

  await waitFor(() => {
    expect(apiRequest).toHaveBeenCalledWith('/api/v1/secrets/s1/value', expect.objectContaining({ token: 'token-1' }));
    expect(apiRequest).toHaveBeenCalledWith('/api/v1/secrets/s1/versions', expect.objectContaining({ token: 'token-1' }));
  });

  expect(screen.getByText('top-secret')).toBeInTheDocument();
  expect(screen.getByText('2026-01-01T00:00:00Z')).toBeInTheDocument();
});

it('queries audit events with from/to filters', async () => {
  installDefaultApiMock();

  render(<App />);
  await userEvent.click(await screen.findByRole('button', { name: 'Sign In' }));

  await userEvent.click(await screen.findByRole('button', { name: 'Audit' }));

  await userEvent.type(screen.getByLabelText('From:'), '2026-03-01T10:00');
  await userEvent.type(screen.getByLabelText('To:'), '2026-03-01T12:00');
  await userEvent.click(screen.getByRole('button', { name: 'Run Query' }));

  await waitFor(() => {
    expect(apiRequest).toHaveBeenCalledWith(
      '/api/v1/audit?from=2026-03-01T10%3A00&to=2026-03-01T12%3A00',
      expect.objectContaining({ token: 'token-1' })
    );
  });
});

it('submits secret ACL entries for selected secret', async () => {
  installDefaultApiMock();

  render(<App />);
  await userEvent.click(await screen.findByRole('button', { name: 'Sign In' }));
  await screen.findByRole('button', { name: 'Apply Secret ACL' });

  const aclCard = screen.getByRole('heading', { name: 'Secret ACL' }).closest('article');
  const aclScope = within(aclCard);
  const checkboxes = aclScope.getAllByRole('checkbox');

  await userEvent.click(checkboxes[1]);
  await userEvent.click(aclScope.getByRole('button', { name: 'Apply Secret ACL' }));

  await waitFor(() => {
    expect(apiRequest).toHaveBeenCalledWith(
      '/api/v1/secrets/s1/acl',
      expect.objectContaining({
        method: 'PUT',
        token: 'token-1',
        body: {
          entries: [
            {
              roleId: 'r1',
              canAdd: false,
              canView: true,
              canChange: false,
              canDelete: false,
            },
          ],
        },
      })
    );
  });
});



