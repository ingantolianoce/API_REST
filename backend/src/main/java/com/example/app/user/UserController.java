package com.example.app.user;

import com.example.app.security.AppUserDetails;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador de REFERENCIA. Reglas que todo controlador nuevo debe copiar:
 *  1. @PreAuthorize con un PERMISO (recurso:accion), nunca con nombres de rol. Lo exige un test ArchUnit.
 *  2. DTOs de entrada con lista blanca de campos: NUNCA tenantId, status, role/is_admin (anti mass assignment).
 *  3. El actor y su tenant vienen del principal de sesion, no de parametros.
 */
@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    public record CreateUserRequest(@NotBlank @Email @Size(max = 254) String email,
                                    @NotBlank @Size(max = 120) String fullName,
                                    @NotEmpty @Size(max = 5) List<@NotBlank @Size(max = 50) String> roles) {}
    public record AssignRolesRequest(@NotEmpty @Size(max = 5) List<@NotBlank @Size(max = 50) String> roles) {}
    public record DisableUserRequest(@NotBlank @Size(max = 200) String reason) {}

    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('user:read')")
    public List<UserService.UserView> list(@AuthenticationPrincipal AppUserDetails me,
                                           @RequestParam(defaultValue = "0") int page,
                                           @RequestParam(defaultValue = "20") int size) {
        return service.list(me, page, size);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('user:read')")
    public UserService.UserView get(@AuthenticationPrincipal AppUserDetails me, @PathVariable UUID id) {
        return service.get(me, id);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('user:create')")
    public ResponseEntity<UserService.CreatedUser> create(@AuthenticationPrincipal AppUserDetails me,
                                                          @Valid @RequestBody CreateUserRequest body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(me, body.email(), body.fullName(), body.roles()));
    }

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('user:assign-role')")
    public UserService.UserView assignRoles(@AuthenticationPrincipal AppUserDetails me, @PathVariable UUID id,
                                            @Valid @RequestBody AssignRolesRequest body) {
        return service.assignRoles(me, id, body.roles());
    }

    @PostMapping("/{id}/disable")
    @PreAuthorize("hasAuthority('user:disable')")
    public ResponseEntity<Void> disable(@AuthenticationPrincipal AppUserDetails me, @PathVariable UUID id,
                                        @Valid @RequestBody DisableUserRequest body) {
        service.disable(me, id, body.reason());
        return ResponseEntity.noContent().build();
    }
}
