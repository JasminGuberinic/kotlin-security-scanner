// Quarkus / MicroProfile specific rules — missing @RolesAllowed/@Authenticated, hardcoded @ConfigProperty secrets.
// Depends on scanner-core for shared base classes and patterns.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Quarkus"
        description = "Detekt security rules for Quarkus: missing @RolesAllowed, Panache raw queries, " +
            "hardcoded @ConfigProperty secrets, OIDC misconfiguration, insecure REST clients, " +
            "GraphQL auth gaps, gRPC without TLS, and 30+ more rules."
    }
}
