# kotlin-security-scanner

> Detekt rules that catch OWASP Top 10 security vulnerabilities in Kotlin applications — at compile time, before they reach production.
> Pick just the module you need: `scanner-core` for any Kotlin project, `scanner-spring-boot` for Spring, `scanner-dropwizard` for JAX-RS.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.10-purple.svg)](https://kotlinlang.org)
[![Detekt](https://img.shields.io/badge/detekt-1.23.7-blue.svg)](https://detekt.dev)
[![CI](https://github.com/JasminGuberinic/kotlin-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/JasminGuberinic/kotlin-security-scanner/actions/workflows/ci.yml)

---

## What it detects

### Core (any Kotlin project)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `WeakCipherModeRule` | A02 | ECB mode, DES, RC4, RC2, Blowfish in `Cipher.getInstance()` |
| `SqlInjectionRule` | A03 | String interpolation or concatenation inside SQL queries |
| `PathTraversalRule` | A03 | `File()` / `Paths.get()` called with non-literal input |
| `HardcodedCredentialsRule` | A07 | Hardcoded passwords, API keys, tokens in source code |
| `InsecureRandomRule` | A07 | `java.util.Random` used for security-sensitive values |
| `SensitiveDataLoggingRule` | A09 | Passwords or tokens interpolated into log statements |
| `SsrfRule` | A10 | `URL()` or `URI()` constructed from a non-literal value |

### Spring Boot

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `MissingAuthorizationRule` | A01 | Spring endpoints without `@PreAuthorize` or `@Secured` |
| `SpringCsrfDisabledRule` | A05 | `.csrf { disable() }` or `.csrf().disable()` |
| `PermissiveCorsRule` | A05 | `allowedOrigins("*")` in CORS configuration |

### Dropwizard / JAX-RS

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `DropwizardMissingAuthRule` | A01 | JAX-RS resources without `@RolesAllowed`, `@DenyAll`, or `@Auth` |
| `InsecureTlsProtocolRule` | A02 | Deprecated TLS 1.0, TLS 1.1, SSLv2, SSLv3 in TLS configuration |

Plus built-in Detekt config covering: MD5/SHA-1 (`ForbiddenMethodCall`), insecure XML parsers and DES imports (`ForbiddenImport`).

---

## Quickstart

**Spring Boot project:**

```kotlin
// build.gradle.kts
plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

dependencies {
    detektPlugins(files("path/to/scanner-core-0.1.0.jar"))
    detektPlugins(files("path/to/scanner-spring-boot-0.1.0.jar"))
}

detekt {
    config.setFrom(files("config/detekt/detekt.yml"))
    buildUponDefaultConfig = true
}
```

**Dropwizard project:**

```kotlin
dependencies {
    detektPlugins(files("path/to/scanner-core-0.1.0.jar"))
    detektPlugins(files("path/to/scanner-dropwizard-0.1.0.jar"))
}
```

**Everything:**

```kotlin
dependencies {
    detektPlugins(files("path/to/scanner-all-0.1.0.jar"))
}
```

Build the JARs locally:

```bash
git clone git@github.com-personal:JasminGuberinic/kotlin-security-scanner.git
cd kotlin-security-scanner
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew assemble
# JARs appear in scanner-*/build/libs/
```

---

## Example findings

```
src/main/kotlin/com/example/UserService.kt:42:
  String interpolation in SQL query — use :namedParam or ? placeholders [SqlInjection]

src/main/kotlin/com/example/AuthConfig.kt:18:
  CSRF protection disabled — let Spring generate tokens instead [SpringCsrfDisabled]

src/main/kotlin/com/example/CryptoService.kt:31:
  Weak cipher 'AES/ECB/PKCS5Padding' — use "AES/GCM/NoPadding" instead [WeakCipherMode]

src/main/kotlin/com/example/UserController.kt:25:
  @GetMapping endpoint is missing @PreAuthorize or @Secured [MissingAuthorization]

src/main/kotlin/com/example/UserResource.kt:14:
  @GET endpoint is missing @RolesAllowed, @DenyAll, or @Auth [DropwizardMissingAuth]
```

---

## Architecture

Multi-module design — pick only what you need.

```
scanner-core/           # Framework-agnostic (A02, A03, A07, A09, A10)
│   core/
│   │   SecurityRule.kt       # Base class — shared AST helpers & reporting
│   │   DetectionPatterns.kt  # All detection patterns, one place
│   ├── a02/  WeakCipherModeRule
│   ├── a03/  SqlInjectionRule · PathTraversalRule
│   ├── a07/  HardcodedCredentialsRule · InsecureRandomRule
│   ├── a09/  SensitiveDataLoggingRule
│   └── a10/  SsrfRule

scanner-spring-boot/    # Spring MVC / Spring Security (A01, A05)
│   ├── a01/  MissingAuthorizationRule
│   └── a05/  SpringCsrfDisabledRule · PermissiveCorsRule

scanner-dropwizard/     # JAX-RS / Dropwizard (A01, A02)
│   ├── a01/  DropwizardMissingAuthRule
│   └── a02/  InsecureTlsProtocolRule

scanner-all/            # Convenience bundle
```

Each rule:
- Lives in the OWASP package that matches its category
- References the [FindSecBugs](https://find-sec-bugs.github.io/bugs.htm) pattern ID
- Has its own test file with positive, negative, and cross-rule isolation tests
- Only imports from `core/` — no coupling between rules

---

## CI

GitHub Actions runs `./gradlew test detekt` on every push and PR.
SARIF results are uploaded directly to GitHub Code Scanning for annotation on PR diffs.

---

## Contributing

```bash
git clone git@github.com-personal:JasminGuberinic/kotlin-security-scanner.git
cd kotlin-security-scanner
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

To add a new rule, open the project in Claude Code and run:

```
/add-security-rule <RuleName> "<description>" <A0X>
```

The skill guides every step: docs lookup, pattern extraction, rule class, test class, registration, and coverage map update.

Manual checklist for PRs:
- [ ] Rule is in the correct `a0X/` package in the right module
- [ ] FindSecBugs pattern ID referenced in the rule comment
- [ ] Patterns added to `DetectionPatterns.kt`
- [ ] Test class has positive, negative, and isolation cases
- [ ] `./gradlew test detekt` passes clean

---

## Roadmap

- [ ] A08 `InsecureDeserializationRule` — `ObjectInputStream.readObject` on untrusted data
- [ ] A03 `SpelInjectionRule` — Spring Expression Language injection
- [ ] A03 `LdapInjectionRule` — LDAP query string concatenation
- [ ] A06 Vulnerable Components — flag known vulnerable dependency versions
- [ ] Publish to Maven Central

---

## License

Apache License 2.0 — same as Spring Boot and Detekt.
See [LICENSE](LICENSE) for details.

---

*Inspired by [FindSecBugs](https://find-sec-bugs.github.io) and the [OWASP Top 10](https://owasp.org/Top10/).*
