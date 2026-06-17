# kotlin-security-scanner

[![CI](https://github.com/JasminGuberinic/kotlin-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/JasminGuberinic/kotlin-security-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.10-purple.svg)](https://kotlinlang.org)
[![Detekt](https://img.shields.io/badge/detekt-1.23.7-blue.svg)](https://detekt.dev)
[![Rules](https://img.shields.io/badge/rules-58-brightgreen.svg)](#owasp-top-10-coverage)

**Detekt plugin that catches OWASP Top 10 security vulnerabilities in Kotlin Spring Boot, Quarkus, and Dropwizard applications — at compile time, in your IDE, with zero infrastructure.**

> **FindSecBugs** works on JVM bytecode and misses Kotlin-specific patterns: coroutines, scope functions, Kotlin DSLs.  
> **SonarQube** security rules require a paid tier or a running server.  
> **CodeQL** requires a full build pipeline and cloud connectivity.  
> This tool runs as a Gradle plugin, offline, on every build, in every developer's environment.

---

## Quick Start

```kotlin
// build.gradle.kts
plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

dependencies {
    // Core rules — works with any Kotlin project
    detektPlugins(files("path/to/scanner-core-0.1.0-SNAPSHOT.jar"))

    // Pick ONE framework module (or use scanner-all for everything)
    detektPlugins(files("path/to/scanner-spring-boot-0.1.0-SNAPSHOT.jar"))
    // detektPlugins(files("path/to/scanner-quarkus-0.1.0-SNAPSHOT.jar"))
    // detektPlugins(files("path/to/scanner-dropwizard-0.1.0-SNAPSHOT.jar"))
}

detekt {
    config.setFrom(files("config/detekt/detekt.yml"))
    buildUponDefaultConfig = true
}
```

Build the JARs:

```bash
git clone https://github.com/JasminGuberinic/kotlin-security-scanner.git
cd kotlin-security-scanner
export JAVA_HOME=/opt/homebrew/opt/openjdk@21  # or your JDK 21 path
./gradlew assemble
# JARs → scanner-*/build/libs/
```

Run:

```bash
./gradlew detekt
```

---

## GitHub Code Scanning (SARIF)

Detekt outputs SARIF natively. Drop this into `.github/workflows/security.yml`:

```yaml
- uses: actions/checkout@v4
- name: Run Kotlin security scan
  run: ./gradlew detekt
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: build/reports/detekt/
```

Results appear inline on pull request diffs — no account, no server, no cost (free for public repos).

---

## OWASP Top 10 coverage

**58 rules** across 4 modules. Every rule has positive, negative, and cross-rule isolation tests.

### Core — any Kotlin project (`scanner-core`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `WeakCipherModeRule` | A02 | ECB mode, DES, RC4, RC2, Blowfish in `Cipher.getInstance()` |
| `WeakHashAlgorithmRule` | A02 | `MessageDigest.getInstance("MD5"\|"SHA-1")` |
| `TrustAllCertsRule` | A02 | Empty `X509TrustManager` — accepts any certificate |
| `HardcodedIvRule` | A02 | `IvParameterSpec(byteArrayOf(...))` with hardcoded bytes |
| `WeakRsaKeyRule` | A02 | `KeyPairGenerator.initialize(≤1024)` |
| `JwtNoneAlgorithmRule` | A02 | `.signWith(NONE)` / `Algorithm.none()` — JWT signature disabled |
| `JwtWeakSecretRule` | A02 | `HMAC256(literal)` / `signWith(literal)` — hardcoded JWT secret |
| `UnsafeCryptoPaddingOracleRule` | A02 | `Cipher.getInstance("AES/CBC/PKCS5Padding")` — padding oracle risk |
| `InsecurePasswordStorageRule` | A02 | `MessageDigest`/`DigestUtils` for passwords — use BCrypt/Argon2 |
| `SqlInjectionRule` | A03 | String interpolation or `+` inside SQL queries |
| `LdapInjectionRule` | A03 | Dynamic strings in `ctx.search()` / `ctx.bind()` |
| `JndiInjectionRule` | A03 | `ctx.lookup(nonLiteral)` — remote JNDI code execution |
| `XpathInjectionRule` | A03 | Dynamic XPath expressions in `xpath.evaluate()` |
| `ReflectionInjectionRule` | A03 | `Class.forName(nonLiteral)` — attacker-chosen class loading |
| `PathTraversalRule` | A03 | `File()` / `Paths.get()` with non-literal input |
| `CommandInjectionRule` | A03 | `Runtime.exec()` / `ProcessBuilder()` with dynamic args |
| `XxeInjectionRule` | A03 | `DocumentBuilderFactory.newInstance()` without DTD disabled |
| `GroovyScriptInjectionRule` | A03 | `GroovyShell().evaluate(nonLiteral)` — script RCE |
| `RegexDenialOfServiceRule` | A06 | `Regex("(a+)+")` — catastrophic backtracking / ReDoS |
| `HardcodedCredentialsRule` | A07 | Hardcoded passwords, API keys, tokens in source code |
| `InsecureRandomRule` | A07 | `java.util.Random` / `ThreadLocalRandom` for security values |
| `InsecureDeserializationRule` | A08 | `ObjectInputStream` — unsafe with untrusted data |
| `JacksonUnsafeDeserializationRule` | A08 | `enableDefaultTyping()` / `@JsonTypeInfo(use=Id.CLASS)` |
| `XmlMapperUnsafeRule` | A08 | `XmlMapper()` constructor — unsafe XML deserialization |
| `SensitiveDataLoggingRule` | A09 | Passwords or tokens interpolated into log statements |
| `SsrfRule` | A10 | `URL()` / `URI()` constructed from a non-literal value |

### Spring Boot (`scanner-spring-boot`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `MissingAuthorizationRule` | A01 | `@GetMapping` etc. without `@PreAuthorize` or `@Secured` |
| `DisabledHttpSecurityRule` | A01 | `anyRequest().permitAll()` in `SecurityFilterChain` |
| `OpenRedirectRule` | A01 | `"redirect:" + variable` in `@Controller` methods |
| `CsrfTokenLeakRule` | A01 | `model.addAttribute("csrf/xsrf...", token)` exposes CSRF token |
| `CoroutineSecurityContextLossRule` | A01 | `suspend fun` with `@PreAuthorize` — security context silently dropped |
| `InsecurePasswordEncoderRule` | A02 | `NoOpPasswordEncoder`, `Md5PasswordEncoder` |
| `MissingHttpsRedirectRule` | A02 | `SecurityFilterChain` without `requiresChannel().requiresSecure()` |
| `InsecureRedisConnectionRule` | A02 | `RedisStandaloneConfiguration`/`LettuceConnectionFactory` without TLS |
| `InsecureSmtpConfigRule` | A02 | `spring.mail.smtp.starttls.enable=false` in `application.properties` |
| `SpelInjectionRule` | A03 | `parseExpression(nonLiteral)` — SpEL RCE |
| `ResponseSplittingRule` | A03 | `response.addHeader(name, nonLiteral)` — CR/LF injection |
| `ELInjectionRule` | A03 | `ELProcessor.eval(nonLiteral)` — EL expression RCE |
| `SpringDataMongoInjectionRule` | A03 | `Criteria.where(nonLiteral)` — MongoDB injection |
| `ThymeleafSSTIRule` | A03 | `templateEngine.process(nonLiteral, ctx)` — Thymeleaf SSTI |
| `MassAssignmentRule` | A04 | `@RequestBody` on a JPA `@Entity` class |
| `SpringCsrfDisabledRule` | A05 | `.csrf { disable() }` / `.csrf().disable()` |
| `PermissiveCorsRule` | A05 | `allowedOrigins("*")` in CORS config |
| `InsecureActuatorExposureRule` | A05 | `management.endpoints.web.exposure.include=*` in properties |
| `WebClientSSRFRule` | A10 | `WebClient.create(nonLiteral)` — WebFlux SSRF |

### Quarkus (`scanner-quarkus`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `QuarkusMissingAuthRule` | A01 | JAX-RS `@GET` etc. without `@RolesAllowed` / `@Authenticated` |
| `QuarkusPermitAllSensitiveRule` | A01 | `@PermitAll` on `@DELETE` / `@PUT` endpoints |
| `PanacheRawQueryRule` | A03 | `PanacheEntity.find(interpolated)` — NoSQL/ORM injection |
| `QuarkusBuildTimeSecretLeakRule` | A05 | Hardcoded secret in `application.properties` — bundled into native image |
| `QuarkusUnsafeHeaderRule` | A05 | `Response.header(name, nonLiteral)` — response splitting |
| `QuarkusHardcodedConfigSecretRule` | A07 | `@ConfigProperty(defaultValue="hardcoded-secret")` |
| `QuarkusOidcInsecureConfigRule` | A07 | `quarkus.oidc.tls.verification=none` or hardcoded OIDC secret |
| `QuarkusReflectionUnsafeRule` | A08 | `@RegisterForReflection` on `Serializable` with `readObject` |

### Dropwizard (`scanner-dropwizard`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `DropwizardMissingAuthRule` | A01 | JAX-RS `@GET` etc. without `@RolesAllowed`, `@DenyAll`, or `@Auth` |
| `DropwizardOpenRedirectRule` | A01 | `Response.seeOther(URI(variable))` — open redirect |
| `InsecureTlsProtocolRule` | A02 | TLS 1.0, TLS 1.1, SSLv2, SSLv3 in TLS configuration |
| `DropwizardUnencryptedJwtSecretRule` | A02 | `setSecretProvider(literal)` — hardcoded JWT secret |
| `DropwizardSelfValidatingELRule` | A03 | `buildConstraintViolationWithTemplate(nonLiteral)` — EL injection (CVE-2020-5245) |
| `InsecureCookieRule` | A05 | `NewCookie(name, value)` without `secure=true` |

---

## Why not FindSecBugs / SonarQube?

| Capability | FindSecBugs | SonarQube | **kotlin-security-scanner** |
|---|---|---|---|
| Kotlin-native (PSI/AST) | ❌ Bytecode only | ⚠️ Partial | ✅ |
| Coroutine security patterns | ❌ Impossible | ❌ | ✅ |
| `let`/`run`/`apply` taint tracking | ❌ | ❌ | ✅ |
| Spring Boot / Quarkus / Dropwizard rules | ⚠️ Java only | ⚠️ Paid tier | ✅ |
| Config file scanning (`.properties`/`.yml`) | ❌ | ❌ | ✅ |
| Infrastructure needed | ❌ | ✅ Server | ❌ |
| Cost | Free | Free / Paid | Free |
| IDE integration (Detekt) | ❌ | ❌ | ✅ |

FindSecBugs misses Kotlin-specific patterns because:
- Kotlin scope functions (`let`, `run`, `apply`, `also`) compile to lambda bytecode that breaks taint analysis
- `suspend fun` — coroutine desugaring makes authorization annotations invisible at bytecode level
- Kotlin's PSI nodes (`KtStringTemplateExpression`, `KtDotQualifiedExpression`) have no direct bytecode equivalent

See [FindSecBugs issue #432](https://github.com/find-sec-bugs/find-sec-bugs/issues/432) and [Kotlin taint analysis limitations](https://arxiv.org/abs/2207.09379).

---

## Example output

```
src/main/kotlin/com/example/UserService.kt:42:9
  String interpolation in SQL — use :namedParam or ? placeholders [SqlInjection]

src/main/kotlin/com/example/AuthConfig.kt:18:5
  anyRequest().permitAll() makes all endpoints public [DisabledHttpSecurity]

src/main/kotlin/com/example/CryptoService.kt:31:9
  AES/ECB — use AES/GCM/NoPadding instead [WeakCipherMode]

src/main/kotlin/com/example/JwtConfig.kt:12:5
  signWith(NONE) disables JWT signature — use HS256/RS256 [JwtNoneAlgorithm]

src/main/kotlin/com/example/UserController.kt:25:5
  suspend fun with @PreAuthorize — security context is silently dropped [CoroutineSecurityContextLoss]
```

---

## Architecture

Multi-module — add only what your project uses.

```
kotlin-security-scanner/
├── scanner-core/            # Framework-agnostic rules (any Kotlin project)
│   └── core/
│       ├── SecurityRule.kt        # Base class — reportAt() helper
│       └── DetectionPatterns.kt   # All patterns, single source of truth
│
├── scanner-spring-boot/     # Spring MVC / Spring Security rules
├── scanner-quarkus/         # Quarkus / MicroProfile / JAX-RS rules
├── scanner-dropwizard/      # Dropwizard / JAX-RS rules
└── scanner-all/             # Convenience bundle (all modules)
```

Design principles:
- Every rule lives in the OWASP package that matches its category (`a01/`–`a10/`)
- All patterns in `DetectionPatterns.kt` — rules never hardcode strings
- No coupling between rules — each only imports from `core/`
- Three test layers per rule: positive (flag), negative (safe), isolation (other rule's fixture)

---

## Adding rules

The project uses a Claude Code skill for consistent rule contributions:

```
/add-security-rule WeakRsaKeyRule core A02
```

The skill reads the pre-researched backlog in `RULES_BACKLOG.md`, generates the rule class, test class, registers it in the provider and `detekt.yml`, and updates the coverage table — all following the established patterns.

Manual checklist for PRs:
- [ ] Rule in correct `a0X/` package in the right module
- [ ] FindSecBugs ID referenced in rule KDoc
- [ ] Patterns added to `DetectionPatterns.kt`
- [ ] Tests: ≥3 positive, ≥2 negative, 1 isolation
- [ ] `./gradlew test detekt` passes clean

---

## Contributing

```bash
git clone https://github.com/JasminGuberinic/kotlin-security-scanner.git
cd kotlin-security-scanner
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

See [`RULES_BACKLOG.md`](RULES_BACKLOG.md) for the pre-researched rule backlog with 20+ more rules ready to implement.

---

## Stack

| Component | Version |
|---|---|
| Kotlin | 2.0.10 |
| Detekt | 1.23.7 |
| Java | 21 |
| Gradle | 8.x |
| AssertJ | 3.26.3 |

---

## License

Apache License 2.0 — same license as Spring Boot and Detekt.

---

*Inspired by [FindSecBugs](https://find-sec-bugs.github.io), [gosec](https://github.com/securego/gosec), and the [OWASP Top 10](https://owasp.org/Top10/).*
