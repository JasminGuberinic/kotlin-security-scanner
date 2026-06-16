// Dropwizard / JAX-RS specific rules — missing @RolesAllowed, insecure resource config.
// Depends on scanner-core for shared base classes and patterns.

dependencies {
    implementation(project(":scanner-core"))
}
