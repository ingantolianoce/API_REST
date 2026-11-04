-- V1: identidad, roles, permisos, consentimientos y auditoria (plantilla de seguridad, secciones 2, 11, 19 y 20).
-- Convenciones: UUID como id, fechas en UTC (timestamptz), borrado logico, control de concurrencia `version`.

CREATE TABLE tenants (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name            text        NOT NULL,
    trade_name            text,
    ruc                   text,
    status                text        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
    privacy_contact_email text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    created_by            uuid,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            uuid,
    deleted_at            timestamptz,
    version               bigint      NOT NULL DEFAULT 0
);

CREATE TABLE roles (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text    NOT NULL UNIQUE,
    description  text,
    is_system    boolean NOT NULL DEFAULT true,
    mfa_required boolean NOT NULL DEFAULT false
);

CREATE TABLE permissions (
    code        text PRIMARY KEY CHECK (code ~ '^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$'),  -- recurso:accion
    description text
);

CREATE TABLE role_permissions (
    role_id         uuid NOT NULL REFERENCES roles(id),
    permission_code text NOT NULL REFERENCES permissions(code),
    PRIMARY KEY (role_id, permission_code)
);

CREATE TABLE users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL REFERENCES tenants(id),
    email                 text        NOT NULL,
    full_name             text        NOT NULL,
    password_hash         text        NOT NULL,                       -- PHC: $argon2id$v=19$m=...,t=...,p=...
    status                text        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('PENDING','ACTIVE','DISABLED')),
    must_change_password  boolean     NOT NULL DEFAULT false,
    email_verified_at     timestamptz,
    mfa_enabled           boolean     NOT NULL DEFAULT false,
    mfa_secret_enc        text,                                       -- TOTP cifrado en reposo (AES-GCM)
    mfa_last_step         bigint,                                     -- anti-reutilizacion del codigo TOTP
    failed_attempts       integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    last_login_at         timestamptz,
    password_changed_at   timestamptz NOT NULL DEFAULT now(),
    deactivated_at        timestamptz,
    deactivation_reason   text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    created_by            uuid,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            uuid,
    deleted_at            timestamptz,
    version               bigint      NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX users_email_uk ON users (lower(email)) WHERE deleted_at IS NULL;
CREATE INDEX users_tenant_idx ON users (tenant_id);

CREATE TABLE user_roles (
    user_id    uuid        NOT NULL REFERENCES users(id),
    role_id    uuid        NOT NULL REFERENCES roles(id),
    tenant_id  uuid        NOT NULL REFERENCES tenants(id),
    granted_by uuid,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id),
    code_hash  text        NOT NULL,                                  -- solo hash, un solo uso
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id);

-- Consentimientos versionados (Ley 7593/2025). Esquema base; cada proyecto lo conecta a sus formularios.
CREATE TABLE consents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES tenants(id),
    subject_type    text        NOT NULL,                             -- 'USER' | 'CUSTOMER' | ...
    subject_id      uuid        NOT NULL,
    purpose         text        NOT NULL,
    policy_version  text        NOT NULL,
    text_sha256     text        NOT NULL,                             -- hash del texto mostrado
    channel         text        NOT NULL,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    created_by      uuid
);
CREATE INDEX consents_subject_idx ON consents (tenant_id, subject_type, subject_id);

-- Solicitudes de derechos del titular (acceso, rectificacion, supresion, oposicion, portabilidad): respuesta <= 30 dias.
CREATE TABLE data_subject_requests (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id),
    subject_type  text        NOT NULL,
    subject_id    uuid,
    request_type  text        NOT NULL CHECK (request_type IN ('ACCESS','RECTIFICATION','ERASURE','OBJECTION','PORTABILITY')),
    status        text        NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','IN_PROGRESS','RESOLVED','REJECTED')),
    received_at   timestamptz NOT NULL DEFAULT now(),
    due_at        timestamptz NOT NULL DEFAULT now() + interval '30 days',
    resolved_at   timestamptz,
    resolution    text,
    handled_by    uuid
);

-- Auditoria SOLO-INSERCION (seccion 11). El trigger impide UPDATE/DELETE/TRUNCATE incluso para el dueno del esquema.
CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event       text        NOT NULL,           -- codigo estable: auth.login.failed, user.role.changed, ...
    tenant_id   uuid,
    user_id     uuid,
    actor_type  text        NOT NULL DEFAULT 'USER',
    ip          text,
    user_agent  text,
    request_id  text,
    resource    text,
    action      text,
    result      text        NOT NULL CHECK (result IN ('OK','DENIED','ERROR')),
    reason      text,
    details     jsonb
);
CREATE INDEX audit_log_time_idx ON audit_log (occurred_at);
CREATE INDEX audit_log_tenant_event_idx ON audit_log (tenant_id, event, occurred_at);

CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log es de solo insercion (% bloqueado)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- Tablas de Spring Session JDBC (sesiones en el servidor => revocables).
CREATE TABLE spring_session (
    primary_id            varchar(64) NOT NULL,   -- ID de 256 bits en base64url (43 caracteres)
    session_id            varchar(64) NOT NULL,
    creation_time         bigint   NOT NULL,
    last_access_time      bigint   NOT NULL,
    max_inactive_interval int      NOT NULL,
    expiry_time           bigint   NOT NULL,
    principal_name        varchar(100),
    CONSTRAINT spring_session_pk PRIMARY KEY (primary_id)
);
CREATE UNIQUE INDEX spring_session_ix1 ON spring_session (session_id);
CREATE INDEX spring_session_ix2 ON spring_session (expiry_time);
CREATE INDEX spring_session_ix3 ON spring_session (principal_name);

CREATE TABLE spring_session_attributes (
    session_primary_id varchar(64) NOT NULL,
    attribute_name     varchar(200) NOT NULL,
    attribute_bytes    bytea NOT NULL,
    CONSTRAINT spring_session_attributes_pk PRIMARY KEY (session_primary_id, attribute_name),
    CONSTRAINT spring_session_attributes_fk FOREIGN KEY (session_primary_id) REFERENCES spring_session(primary_id) ON DELETE CASCADE
);
