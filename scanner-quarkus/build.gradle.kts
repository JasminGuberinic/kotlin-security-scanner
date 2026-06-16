// Quarkus / MicroProfile specific rules — missing @RolesAllowed/@Authenticated, hardcoded @ConfigProperty secrets.
// Depends on scanner-core for shared base classes and patterns.

dependencies {
    implementation(project(":scanner-core"))
}
