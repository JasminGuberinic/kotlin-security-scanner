// Ktor specific rules — missing authentication, insecure session cookies, permissive CORS.
// Depends on scanner-core for shared base classes and patterns.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Ktor"
        description = "Detekt security rules for Ktor: missing route authentication, insecure cookies, " +
            "permissive CORS, weak JWT secrets, missing SSL redirect, missing rate limiting, " +
            "Exposed ORM injection, hardcoded database passwords, and more."
    }
}
