// Vert.x specific rules — TLS trust-all, permissive CORS, unbounded body handler,
// open event-bus bridge, insecure cookies. Applies to standalone Vert.x and to
// frameworks built on it. Depends on scanner-core for shared base classes and patterns.

plugins {
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(project(":scanner-core"))
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Vert.x"
        description = "Detekt security rules for Eclipse Vert.x: disabled TLS verification (trustAll), " +
            "permissive CORS, unbounded BodyHandler, open SockJS event-bus bridge, insecure cookies, and more."
    }
}
