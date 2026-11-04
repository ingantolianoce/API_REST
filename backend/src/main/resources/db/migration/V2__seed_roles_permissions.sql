-- V2: catalogo base de permisos y roles de sistema (seccion 2). Cada proyecto agrega los suyos en nuevas migraciones.
-- No hay usuarios ni credenciales aqui: el primer superadmin se crea con el bootstrap seguro (BootstrapAdminRunner).

INSERT INTO permissions (code, description) VALUES
    ('user:read',        'Ver usuarios del comercio'),
    ('user:create',      'Crear usuarios del comercio'),
    ('user:update',      'Editar usuarios del comercio'),
    ('user:disable',     'Desactivar usuarios'),
    ('user:assign-role', 'Asignar roles a usuarios'),
    ('audit:read',       'Consultar la auditoria del comercio'),
    ('tenant:read',      'Ver datos del comercio'),
    ('tenant:update',    'Editar datos del comercio');

INSERT INTO roles (name, description, mfa_required) VALUES
    ('superadmin',   'Administracion total. Minimas cuentas. MFA obligatorio.', true),
    ('admin',        'Administra usuarios y configuracion del comercio. MFA obligatorio.', true),
    ('gestor',       'Gestiona operaciones y ve usuarios. MFA obligatorio.', true),
    ('operador',     'Operacion diaria sin acceso a administracion.', false),
    ('solo_lectura', 'Consulta sin modificar.', false);

-- superadmin: todos los permisos
INSERT INTO role_permissions SELECT r.id, p.code FROM roles r CROSS JOIN permissions p WHERE r.name = 'superadmin';
-- admin: todo menos editar el comercio
INSERT INTO role_permissions SELECT r.id, p.code FROM roles r CROSS JOIN permissions p
    WHERE r.name = 'admin' AND p.code <> 'tenant:update';
-- gestor
INSERT INTO role_permissions SELECT r.id, p.code FROM roles r CROSS JOIN permissions p
    WHERE r.name = 'gestor' AND p.code IN ('user:read', 'audit:read', 'tenant:read');
-- operador / solo_lectura
INSERT INTO role_permissions SELECT r.id, p.code FROM roles r CROSS JOIN permissions p
    WHERE r.name = 'operador' AND p.code IN ('tenant:read');
INSERT INTO role_permissions SELECT r.id, p.code FROM roles r CROSS JOIN permissions p
    WHERE r.name = 'solo_lectura' AND p.code IN ('user:read', 'tenant:read');
