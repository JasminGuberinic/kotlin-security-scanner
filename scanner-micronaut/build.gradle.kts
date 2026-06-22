// Micronaut specific rules — missing @Secured, hardcoded secrets, insecure config, injection patterns.
// Depends on scanner-core for shared base classes and patterns.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Micronaut"
        description = "Detekt security rules for Micronaut: missing @Secured, hardcoded secrets, " +
            "insecure SSL config, Micronaut Data query injection, unsafe @Body types, and more."
    }
}
