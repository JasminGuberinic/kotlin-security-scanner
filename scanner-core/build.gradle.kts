// Framework-agnostic rules — SQL injection, weak crypto, path traversal,
// hardcoded secrets, insecure random, SSRF, sensitive logging.
// No framework dependencies: works with any Kotlin project.

plugins {
    id("com.vanniktech.maven.publish")
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Core"
        description = "Detekt rules for OWASP Top 10 security vulnerabilities in Kotlin: " +
            "SQL/command injection, weak crypto, path traversal, hardcoded credentials, " +
            "insecure random, SSRF, unsafe deserialization, and sensitive data logging. " +
            "Framework-agnostic — works with any Kotlin/JVM project."
    }
}
