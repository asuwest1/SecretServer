CREATE TABLE users (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    username NVARCHAR(64) NOT NULL UNIQUE,
    display_name NVARCHAR(128) NOT NULL,
    email NVARCHAR(256) NOT NULL UNIQUE,
    password_hash NVARCHAR(512) NOT NULL,
    mfa_secret_enc NVARCHAR(MAX) NULL,
    mfa_pending_secret_enc NVARCHAR(MAX) NULL,
    mfa_enabled BIT NOT NULL DEFAULT 0,
    is_active BIT NOT NULL DEFAULT 1,
    is_super_admin BIT NOT NULL DEFAULT 0,
    failed_attempts SMALLINT NOT NULL DEFAULT 0,
    locked_until DATETIME2 NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    last_login_at DATETIME2 NULL
);

CREATE TABLE roles (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    name NVARCHAR(64) NOT NULL UNIQUE,
    description NVARCHAR(256) NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE user_roles (
    user_id UNIQUEIDENTIFIER NOT NULL,
    role_id UNIQUEIDENTIFIER NOT NULL,
    assigned_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    assigned_by UNIQUEIDENTIFIER NULL,
    CONSTRAINT PK_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT FK_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT FK_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE folders (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    name NVARCHAR(128) NOT NULL,
    parent_folder_id UNIQUEIDENTIFIER NULL,
    created_by UNIQUEIDENTIFIER NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_folders_parent FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
    CONSTRAINT FK_folders_created_by FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE secrets (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    folder_id UNIQUEIDENTIFIER NOT NULL,
    name NVARCHAR(256) NOT NULL,
    secret_type NVARCHAR(32) NOT NULL,
    username NVARCHAR(256) NULL,
    url NVARCHAR(2048) NULL,
    notes_enc NVARCHAR(MAX) NULL,
    tags NVARCHAR(MAX) NULL,
    value_enc NVARCHAR(MAX) NOT NULL,
    dek_enc NVARCHAR(MAX) NOT NULL,
    is_deleted BIT NOT NULL DEFAULT 0,
    deleted_at DATETIME2 NULL,
    purge_after DATETIME2 NULL,
    created_by UNIQUEIDENTIFIER NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_by UNIQUEIDENTIFIER NOT NULL,
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_secrets_folder FOREIGN KEY (folder_id) REFERENCES folders(id)
);

CREATE TABLE secret_versions (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    secret_id UNIQUEIDENTIFIER NOT NULL,
    version_num SMALLINT NOT NULL,
    value_enc NVARCHAR(MAX) NOT NULL,
    dek_enc NVARCHAR(MAX) NOT NULL,
    changed_by UNIQUEIDENTIFIER NOT NULL,
    changed_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_secret_versions UNIQUE(secret_id, version_num),
    CONSTRAINT FK_secret_versions_secret FOREIGN KEY (secret_id) REFERENCES secrets(id)
);

CREATE TABLE secret_acl (
    secret_id UNIQUEIDENTIFIER NOT NULL,
    role_id UNIQUEIDENTIFIER NOT NULL,
    can_add BIT NOT NULL DEFAULT 0,
    can_view BIT NOT NULL DEFAULT 0,
    can_change BIT NOT NULL DEFAULT 0,
    can_delete BIT NOT NULL DEFAULT 0,
    granted_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    granted_by UNIQUEIDENTIFIER NULL,
    CONSTRAINT PK_secret_acl PRIMARY KEY (secret_id, role_id)
);

CREATE TABLE folder_acl (
    folder_id UNIQUEIDENTIFIER NOT NULL,
    role_id UNIQUEIDENTIFIER NOT NULL,
    can_add BIT NOT NULL DEFAULT 0,
    can_view BIT NOT NULL DEFAULT 0,
    can_change BIT NOT NULL DEFAULT 0,
    can_delete BIT NOT NULL DEFAULT 0,
    CONSTRAINT PK_folder_acl PRIMARY KEY (folder_id, role_id)
);

CREATE TABLE api_tokens (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    user_id UNIQUEIDENTIFIER NOT NULL,
    name NVARCHAR(64) NOT NULL,
    token_hash NVARCHAR(256) NOT NULL UNIQUE,
    last_used DATETIME2 NULL,
    expires_at DATETIME2 NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_api_tokens_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE audit_log (
    id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    event_time DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    user_id UNIQUEIDENTIFIER NULL,
    username NVARCHAR(64) NULL,
    action NVARCHAR(64) NOT NULL,
    resource NVARCHAR(32) NULL,
    resource_id UNIQUEIDENTIFIER NULL,
    secret_name NVARCHAR(256) NULL,
    ip_address NVARCHAR(64) NULL,
    user_agent NVARCHAR(512) NULL,
    detail NVARCHAR(MAX) NULL
);

CREATE TABLE refresh_sessions (
    jti NVARCHAR(128) NOT NULL PRIMARY KEY,
    parent_jti NVARCHAR(128) NULL,
    user_id UNIQUEIDENTIFIER NOT NULL,
    token_hash NVARCHAR(256) NOT NULL,
    expires_at DATETIME2 NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    revoked_at DATETIME2 NULL,
    last_used_at DATETIME2 NULL,
    CONSTRAINT FK_refresh_sessions_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE revoked_token_jti (
    jti NVARCHAR(128) NOT NULL PRIMARY KEY,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

DENY UPDATE, DELETE ON audit_log TO public;
