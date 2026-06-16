# kotlin-security-scanner

> Detekt rules that catch OWASP Top 10 security vulnerabilities in Kotlin Spring Boot applications — at compile time, before they reach production.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.10-purple.svg)](https://kotlinlang.org)
[![Detekt](https://img.shields.io/badge/detekt-1.23.7-blue.svg)](https://detekt.dev)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.0-green.svg)](https://spring.io/projects/spring-boot)

---

## What it detects

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `MissingAuthorizationRule` | A01 | Spring endpoints without `@PreAuthorize` or `@Secured` |
| `WeakCipherModeRule` | A02 | ECB mode, DES, RC4, RC2, Blowfish in `Cipher.getInstance()` |
| `SqlInjectionRule` | A03 | String interpolation or concatenation inside SQL queries |
| `PathTraversalRule` | A03 | `File()` / `Paths.get()` called with non-literal input |
| `SpringCsrfDisabledRule` | A05 | `.csrf { disable() }` or `.csrf().disable()` |
| `PermissiveCorsRule` | A05 | `allowedOrigins("*")` in CORS configuration |
| `HardcodedCredentialsRule` | A07 | Hardcoded passwords, API keys, tokens in source code |
| `InsecureRandomRule` | A07 | `java.util.Random` used for security-sensitive values |
| `SensitiveDataLoggingRule` | A09 | Passwords or tokens interpolated into log statements |
| `SsrfRule` | A10 | `URL()` or `URI()` constructed from a non-literal value |

Plus built-in Detekt config covering: MD5/SHA-1 (`ForbiddenMethodCall`), insecure XML parsers and DES imports (`ForbiddenImport`).

---

## Quickstart

**1. Add the Detekt plugin to your Spring Boot project:**

```kotlin
// build.gradle.kts
plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

dependencies {
    detektPlugins("io.github.jasminguberinic:kotlin-security-scanner:0.1.0") // coming soon to Maven Central
}

detekt {
    config.setFrom(files("config/detekt/detekt.yml"))
    buildUponDefaultConfig = true
}
```

> Until the artifact is published, clone this repo and use `detektPlugins(files("path/to/kotlin-security-scanner.jar"))`.

**2. Copy the config:**

```bash
mkdir -p config/detekt
curl -o config/detekt/detekt.yml \
  https://raw.githubusercontent.com/JasminGuberinic/kotlin-security-scanner/main/config/detekt/detekt.yml
```

**3. Run:**

```bash
./gradlew detekt
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
  Function 'deleteUser' is a Spring endpoint without @PreAuthorize or @Secured [MissingAuthorization]
```

---

## Architecture

Built to grow. Every rule follows the same structure so contributors (human or AI) can add coverage without touching existing rules.

```
detekt/
├── core/
│   ├── SecurityRule.kt       # Base class — shared AST helpers & reporting
│   └── DetectionPatterns.kt  # All detection patterns, one place
│
├── a01/  MissingAuthorizationRule
├── a02/  WeakCipherModeRule
├── a03/  SqlInjectionRule · PathTraversalRule
├── a05/  SpringCsrfDisabledRule · PermissiveCorsRule
├── a07/  HardcodedCredentialsRule · InsecureRandomRule
├── a09/  SensitiveDataLoggingRule
└── a10/  SsrfRule
```

Each rule:
- Lives in the OWASP package that matches its category
- References the [FindSecBugs](https://find-sec-bugs.github.io/bugs.htm) pattern ID
- Has its own test file with positive, negative, and cross-rule isolation tests
- Only imports from `core/` — no coupling between rules

---

## Contributing

```bash
git clone git@github.com:JasminGuberinic/kotlin-security-scanner.git
cd kotlin-security-scanner
export JAVA_HOME=/opt/homebrew/opt/openjdk@21   # or your JDK 21 path
./gradlew test detekt
```

To add a new rule, open the project in Claude Code and run:

```
/add-security-rule <RuleName> "<description>" <A0X>
```

The skill guides every step: docs lookup, pattern extraction, rule class, test class, registration, and coverage map update.

Manual checklist for PRs:
- [ ] Rule is in the correct `a0X/` package
- [ ] FindSecBugs pattern ID referenced in the rule comment
- [ ] Patterns added to `DetectionPatterns.kt`
- [ ] Test class has positive, negative, and isolation cases
- [ ] `./gradlew test detekt` passes clean

---

## Roadmap

- [ ] A08 `InsecureDeserializationRule` — `ObjectInputStream.readObject` on untrusted data
- [ ] A03 `SpelInjectionRule` — Spring Expression Language injection
- [ ] A03 `LdapInjectionRule` — LDAP query string concatenation
- [ ] Publish to Maven Central
- [ ] GitHub Actions CI with SARIF upload to GitHub Code Scanning

---

## License

Apache License 2.0 — same as Spring Boot and Detekt.
See [LICENSE](LICENSE) for details.

---

*Inspired by [FindSecBugs](https://find-sec-bugs.github.io) and the [OWASP Top 10](https://owasp.org/Top10/).*
