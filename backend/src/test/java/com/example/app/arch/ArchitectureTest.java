package com.example.app.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Reglas de arquitectura que hacen cumplir "denegar por defecto" y "autorizar siempre en el servidor":
 * un endpoint nuevo SIN @PreAuthorize rompe el build.
 */
@AnalyzeClasses(packages = "com.example.app", importOptions = ImportOption.DoNotIncludeTests.class)
class ArchitectureTest {

    @ArchTest
    static final ArchRule everyEndpointDeclaresItsAuthorization = methods()
            .that().areAnnotatedWith(GetMapping.class)
            .or().areAnnotatedWith(PostMapping.class)
            .or().areAnnotatedWith(PutMapping.class)
            .or().areAnnotatedWith(PatchMapping.class)
            .or().areAnnotatedWith(DeleteMapping.class)
            .or().areAnnotatedWith(RequestMapping.class)
            .should().beAnnotatedWith(PreAuthorize.class)
            .because("todo endpoint debe declarar su permiso (@PreAuthorize); 'permitAll()' debe ser explicito");

    @ArchTest
    static final ArchRule controllersDoNotTouchJdbcDirectly = noClasses()
            .that().haveSimpleNameEndingWith("Controller")
            .should().dependOnClassesThat().haveFullyQualifiedName("org.springframework.jdbc.core.simple.JdbcClient")
            .because("los controladores delegan en servicios/repositorios (capas de validacion y datos)");

    @ArchTest
    static final ArchRule noRoleNameChecksInCode = methods()
            .that().areAnnotatedWith(PreAuthorize.class)
            .should(new com.tngtech.archunit.lang.ArchCondition<com.tngtech.archunit.core.domain.JavaMethod>("no usar hasRole/hasAnyRole") {
                @Override
                public void check(com.tngtech.archunit.core.domain.JavaMethod m, com.tngtech.archunit.lang.ConditionEvents events) {
                    String v = m.getAnnotationOfType(PreAuthorize.class).value();
                    if (v.contains("hasRole") || v.contains("hasAnyRole")) {
                        events.add(com.tngtech.archunit.lang.SimpleConditionEvent.violated(m, m.getFullName() + " usa nombres de rol: " + v));
                    }
                }
            })
            .because("el codigo verifica PERMISOS (recurso:accion), no nombres de rol");
}
