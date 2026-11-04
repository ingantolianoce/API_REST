-- Repetible: reaplica los privilegios del usuario de la aplicacion tras cada migracion.
-- Minimo privilegio: sin DDL; audit_log solo SELECT/INSERT; DELETE solo donde el modelo lo exige.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
        GRANT USAGE ON SCHEMA public TO app_runtime;
        GRANT SELECT, INSERT, UPDATE ON
            tenants, roles, permissions, role_permissions, users, user_roles, recovery_codes,
            consents, data_subject_requests, spring_session, spring_session_attributes
            TO app_runtime;
        GRANT DELETE ON user_roles, recovery_codes, spring_session, spring_session_attributes TO app_runtime;
        GRANT SELECT, INSERT ON audit_log TO app_runtime;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime;
        -- flyway_schema_history: el runtime no la ve
        REVOKE ALL ON flyway_schema_history FROM app_runtime;
    END IF;
END $$;
