// Convenience module — bundles core + spring-boot + dropwizard + quarkus + ktor in one artifact.
// Add this as detektPlugins if you want full coverage without picking modules.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
    implementation(project(":scanner-spring-boot"))
    implementation(project(":scanner-dropwizard"))
    implementation(project(":scanner-quarkus"))
    implementation(project(":scanner-ktor"))
    implementation(project(":scanner-micronaut"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — All Rules"
        description = "Detekt security plugin covering OWASP Top 10 for Kotlin/JVM — 153+ rules across " +
            "Spring Boot, Quarkus, Dropwizard, and Ktor. Catches SQL injection, weak crypto, " +
            "hardcoded secrets, insecure config, and more at compile time in CI. " +
            "Convenience bundle: includes all framework modules in one artifact."
    }
}
