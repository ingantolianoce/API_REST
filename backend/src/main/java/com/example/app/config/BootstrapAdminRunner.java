package com.example.app.config;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.security.PasswordGenerator;
import com.example.app.security.PasswordHasher;
import com.example.app.user.UserRepository;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Bootstrap seguro del primer superadmin (no hay credenciales por defecto en ningun entorno).
 * Solo actua si app.bootstrap.enabled=true Y no existe ningun usuario. Genera una contrasena aleatoria de un solo uso,
 * la escribe en un archivo con permisos 0600 (NUNCA en logs) y fuerza el cambio y el alta de MFA en el primer ingreso.
 * El operador lee el archivo, lo borra y desactiva el bootstrap.
 */
@Component
public class BootstrapAdminRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(BootstrapAdminRunner.class);

    private final AppProperties props;
    private final UserRepository users;
    private final PasswordHasher hasher;
    private final AuditService audit;
    private final TransactionTemplate tx;

    public BootstrapAdminRunner(AppProperties props, UserRepository users, PasswordHasher hasher, AuditService audit,
                                TransactionTemplate tx) {
        this.props = props;
        this.users = users;
        this.hasher = hasher;
        this.audit = audit;
        this.tx = tx;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        var cfg = props.bootstrap();
        if (!cfg.enabled()) return;
        if (users.countAll() > 0) {
            log.info("Bootstrap activo pero ya existen usuarios: no se crea nada. Desactive app.bootstrap.enabled.");
            return;
        }
        Path file = Path.of(cfg.passwordFile());
        if (Files.exists(file)) throw new IllegalStateException("El archivo de bootstrap ya existe; revise y borrelo");

        String password = PasswordGenerator.oneTime();
        // Primero el archivo (con permisos estrictos) para no perder la unica copia de la clave.
        Files.createFile(file, PosixFilePermissions.asFileAttribute(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
        Files.writeString(file, "email=" + cfg.adminEmail() + "\npassword=" + password + "\n", StandardCharsets.UTF_8);

        tx.executeWithoutResult(s -> {
            UUID tenant = users.insertTenant(cfg.tenantName());
            UUID id = users.insert(tenant, cfg.adminEmail().strip().toLowerCase(java.util.Locale.ROOT), "Administrador inicial",
                    hasher.hash(password), true, null);
            users.replaceRoles(id, tenant, Set.of("superadmin"), null);
            audit.recordFor(tenant, id, "bootstrap.superadmin.created", Result.OK, "user:" + id, "create", null, Map.of());
        });
        log.warn("Superadmin inicial creado. Credencial de un solo uso en el archivo configurado (permisos 0600). "
                + "Leala, borre el archivo y desactive app.bootstrap.enabled.");
    }
}
