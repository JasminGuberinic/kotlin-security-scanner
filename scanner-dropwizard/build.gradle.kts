// Dropwizard / JAX-RS specific rules — missing @RolesAllowed, insecure resource config.
// Depends on scanner-core for shared base classes and patterns.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Dropwizard"
        description = "Detekt security rules for Dropwizard: missing @RolesAllowed, insecure TLS config, " +
            "JDBI SQL injection, EL injection in @SelfValidating, insecure cookies, " +
            "admin connector exposure, Jackson polymorphism deserialization, and more."
    }
}
