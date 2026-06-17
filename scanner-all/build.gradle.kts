// Convenience module — bundles core + spring-boot + dropwizard + quarkus in one artifact.
// Add this as detektPlugins if you want full coverage without picking modules.

dependencies {
    implementation(project(":scanner-core"))
    implementation(project(":scanner-spring-boot"))
    implementation(project(":scanner-dropwizard"))
    implementation(project(":scanner-quarkus"))
    implementation(project(":scanner-ktor"))
}
