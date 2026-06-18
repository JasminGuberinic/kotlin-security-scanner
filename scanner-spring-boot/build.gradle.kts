// Spring Boot specific rules — missing @PreAuthorize, CSRF disabled, permissive CORS.
// Depends on scanner-core for shared base classes and patterns.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Spring Boot"
        description = "Detekt security rules for Spring Boot: missing @PreAuthorize, CSRF disabled, " +
            "permissive CORS, SpEL injection, Thymeleaf SSTI, insecure actuator exposure, " +
            "hardcoded datasource passwords, weak BCrypt rounds, JWT issues, and 45+ more rules."
    }
}
