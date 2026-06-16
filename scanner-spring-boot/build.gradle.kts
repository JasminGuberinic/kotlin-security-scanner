// Spring Boot specific rules — missing @PreAuthorize, CSRF disabled, permissive CORS.
// Depends on scanner-core for shared base classes and patterns.

dependencies {
    implementation(project(":scanner-core"))
}
