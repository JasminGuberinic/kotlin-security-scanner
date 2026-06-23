# kotlin-security-scanner

Detekt plugin that detects OWASP Top 10 security vulnerabilities in
Kotlin applications at compile time — with module-level picks for
Spring Boot, Quarkus, Dropwizard, Ktor, Micronaut, or any Kotlin project.

**201 rules across 6 modules, 1262 tests. Published to Maven Central as
`io.github.jasminguberinic:scanner-*:0.2.0`.** Rules are active by default
(`SecurityRule.active` defaults to true); disable any with `active: false`.

Designed to grow: every rule follows the same architecture so contributors
(human or AI) can add new coverage without touching existing rules.

> The OWASP coverage table below is a historical/representative subset, not the full
> list — the authoritative inventory is the rule classes themselves and the README.
> When adding a rule, registration is verified by `scanner-e2e` (every rule must fire)
> rather than by this table.

---

## Architecture

```
kotlin-security-scanner/
│
├── scanner-core/                  # Framework-agnostic rules
│   └── src/main/kotlin/com/jasmin/security/detekt/
│       ├── core/
│       │   ├── SecurityRule.kt          # Base class — shared AST helpers & reporting
│       │   └── DetectionPatterns.kt     # All detection patterns, grouped by OWASP
│       ├── a02/  WeakCipherModeRule
│       ├── a03/  SqlInjectionRule · PathTraversalRule
│       ├── a07/  HardcodedCredentialsRule · InsecureRandomRule
│       ├── a09/  SensitiveDataLoggingRule
│       ├── a10/  SsrfRule
│       └── CoreRuleSetProvider.kt       # SPI — ruleSetId = "security-core"
│
├── scanner-spring-boot/           # Spring MVC / Security rules
│   └── src/main/kotlin/com/jasmin/security/detekt/
│       ├── a01/  MissingAuthorizationRule
│       ├── a05/  SpringCsrfDisabledRule · PermissiveCorsRule
│       └── SpringBootRuleSetProvider.kt # SPI — ruleSetId = "security-spring-boot"
│
├── scanner-dropwizard/            # JAX-RS / Dropwizard rules
│   └── src/main/kotlin/com/jasmin/security/detekt/
│       ├── a01/  DropwizardMissingAuthRule
│       ├── a02/  InsecureTlsProtocolRule
│       └── DropwizardRuleSetProvider.kt # SPI — ruleSetId = "security-dropwizard"
│
└── scanner-all/                   # Convenience bundle — core + spring-boot + dropwizard

config/detekt/detekt.yml         # Detekt config — built-in + all custom rule sections
.github/workflows/ci.yml         # CI: test + detekt + SARIF upload on every PR
```

### Core principles

| Principle | How it's applied |
|---|---|
| Single source of truth | All patterns live in `DetectionPatterns.kt` |
| Reads like prose | Each rule: 1 visit method + small named predicates |
| No cross-rule coupling | Rules only import from `core/` |
| Isolation guaranteed | Every test has a negative case from another rule |
| AI-extensible | `/add-security-rule` skill drives consistent contributions |

---

## OWASP coverage

| OWASP 2021 | Rule | Module | FindSecBugs ID | Status |
|---|---|---|---|---|
| A01 Broken Access Control | `MissingAuthorizationRule` | spring-boot | SPRING_ENDPOINT | ✅ |
| A01 Broken Access Control | `DisabledHttpSecurityRule` | spring-boot | SPRING_CSRF_PROTECTION_DISABLED | ✅ |
| A01 Broken Access Control | `OpenRedirectRule` | spring-boot | SPRING_UNVALIDATED_REDIRECT | ✅ |
| A01 Broken Access Control | `CsrfTokenLeakRule` | spring-boot | CSRF_TOKEN_INTROSPECTION | ✅ |
| A01 Broken Access Control | `CoroutineSecurityContextLossRule` | spring-boot | — (Kotlin-unique) | ✅ |
| A01 Broken Access Control | `DropwizardMissingAuthRule` | dropwizard | JAXRS_ENDPOINT | ✅ |
| A01 Broken Access Control | `DropwizardOpenRedirectRule` | dropwizard | UNVALIDATED_REDIRECT | ✅ |
| A01 Broken Access Control | `QuarkusMissingAuthRule` | quarkus | JAXRS_ENDPOINT | ✅ |
| A01 Broken Access Control | `QuarkusPermitAllSensitiveRule` | quarkus | JAXRS_ENDPOINT | ✅ |
| A02 Cryptographic Failures | `WeakCipherModeRule` | core | ECB_MODE, DES_USAGE | ✅ |
| A02 Cryptographic Failures | `WeakHashAlgorithmRule` | core | WEAK_MESSAGE_DIGEST_MD5 | ✅ |
| A02 Cryptographic Failures | `TrustAllCertsRule` | core | WEAK_TRUST_MANAGER | ✅ |
| A02 Cryptographic Failures | `HardcodedIvRule` | core | STATIC_IV | ✅ |
| A02 Cryptographic Failures | `WeakRsaKeyRule` | core | WEAK_KEY_SIZE | ✅ |
| A02 Cryptographic Failures | `JwtNoneAlgorithmRule` | core | — | ✅ |
| A02 Cryptographic Failures | `JwtWeakSecretRule` | core | HARD_CODE_KEY | ✅ |
| A02 Cryptographic Failures | `UnsafeCryptoPaddingOracleRule` | core | PADDING_ORACLE | ✅ |
| A02 Cryptographic Failures | `InsecurePasswordStorageRule` | core | WEAK_MESSAGE_DIGEST_* | ✅ |
| A02 Cryptographic Failures | `InsecurePasswordEncoderRule` | spring-boot | WEAK_PASSWORD_ENCODER | ✅ |
| A02 Cryptographic Failures | `MissingHttpsRedirectRule` | spring-boot | INSECURE_CHANNEL | ✅ |
| A02 Cryptographic Failures | `InsecureRedisConnectionRule` | spring-boot | UNENCRYPTED_SOCKET | ✅ |
| A02 Cryptographic Failures | `InsecureSmtpConfigRule` | spring-boot | INSECURE_SMTP_SSL | ✅ |
| A02 Cryptographic Failures | `InsecureTlsProtocolRule` | dropwizard | SSL_CONTEXT | ✅ |
| A02 Cryptographic Failures | `DropwizardUnencryptedJwtSecretRule` | dropwizard | HARD_CODE_KEY | ✅ |
| A03 Injection — SQL | `SqlInjectionRule` | core | SQL_INJECTION_JPA | ✅ |
| A03 Injection — LDAP | `LdapInjectionRule` | core | LDAP_INJECTION | ✅ |
| A03 Injection — XPath | `XpathInjectionRule` | core | XPATH_INJECTION | ✅ |
| A03 Injection — JNDI | `JndiInjectionRule` | core | JNDI_INJECTION | ✅ |
| A03 Injection — Reflection | `ReflectionInjectionRule` | core | REFLECTOR_BASED_INJECTION | ✅ |
| A03 Injection — Path Traversal | `PathTraversalRule` | core | PATH_TRAVERSAL_IN | ✅ |
| A03 Injection — Command | `CommandInjectionRule` | core | COMMAND_INJECTION | ✅ |
| A03 Injection — XXE | `XxeInjectionRule` | core | XXE_DTD | ✅ |
| A03 Injection — Groovy Script | `GroovyScriptInjectionRule` | core | SCRIPT_ENGINE_INJECTION | ✅ |
| A03 Injection — SpEL | `SpelInjectionRule` | spring-boot | SPEL_INJECTION | ✅ |
| A03 Injection — Response Splitting | `ResponseSplittingRule` | spring-boot | HTTP_RESPONSE_SPLITTING | ✅ |
| A03 Injection — EL | `ELInjectionRule` | spring-boot | EL_INJECTION | ✅ |
| A03 Injection — MongoDB | `SpringDataMongoInjectionRule` | spring-boot | SQL_INJECTION_JPA | ✅ |
| A03 Injection — Thymeleaf SSTI | `ThymeleafSSTIRule` | spring-boot | — | ✅ |
| A03 Injection — Panache | `PanacheRawQueryRule` | quarkus | SQL_INJECTION_JPA | ✅ |
| A03 Injection — EL | `DropwizardSelfValidatingELRule` | dropwizard | EL_INJECTION | ✅ |
| A04 Insecure Design | `MassAssignmentRule` | spring-boot | MASS_ASSIGNMENT | ✅ |
| A05 Security Misconfiguration | `SpringCsrfDisabledRule` | spring-boot | SPRING_CSRF_PROTECTION_DISABLED | ✅ |
| A05 Security Misconfiguration | `PermissiveCorsRule` | spring-boot | PERMISSIVE_CORS | ✅ |
| A05 Security Misconfiguration | `InsecureActuatorExposureRule` | spring-boot | — | ✅ |
| A05 Security Misconfiguration | `QuarkusBuildTimeSecretLeakRule` | quarkus | — | ✅ |
| A05 Security Misconfiguration | `QuarkusUnsafeHeaderRule` | quarkus | HTTP_RESPONSE_SPLITTING | ✅ |
| A05 Security Misconfiguration | `InsecureCookieRule` | dropwizard | INSECURE_COOKIE | ✅ |
| A06 Vulnerable Components | `RegexDenialOfServiceRule` | core | REDOS | ✅ |
| A07 Hardcoded Secrets | `HardcodedCredentialsRule` | core | HARD_CODE_PASSWORD | ✅ |
| A07 Insecure Random | `InsecureRandomRule` | core | PREDICTABLE_RANDOM | ✅ |
| A07 Authentication Failures | `QuarkusHardcodedConfigSecretRule` | quarkus | HARD_CODE_PASSWORD | ✅ |
| A07 Authentication Failures | `QuarkusOidcInsecureConfigRule` | quarkus | — | ✅ |
| A08 Deserialization | `InsecureDeserializationRule` | core | OBJECT_DESERIALIZATION | ✅ |
| A08 Deserialization | `JacksonUnsafeDeserializationRule` | core | JACKSON_UNSAFE_DESERIALIZATION | ✅ |
| A08 Deserialization | `XmlMapperUnsafeRule` | core | JACKSON_UNSAFE_DESERIALIZATION | ✅ |
| A08 Deserialization | `QuarkusReflectionUnsafeRule` | quarkus | OBJECT_DESERIALIZATION | ✅ |
| A09 Sensitive Logging | `SensitiveDataLoggingRule` | core | INFORMATION_EXPOSURE | ✅ |
| A10 SSRF | `SsrfRule` | core | URLCONNECTION_SSRF_FD | ✅ |
| A10 SSRF | `WebClientSSRFRule` | spring-boot | URLCONNECTION_SSRF_FD | ✅ |
| A01 Auth | `AsyncSecurityContextLossRule` | spring-boot | — (Spring-specific) | ✅ |
| A01 Auth | `FeignClientInsecureUrlRule` | spring-boot | — | ✅ |
| A02 Crypto | `JwtSecretInPropertiesRule` | spring-boot | HARD_CODE_KEY | ✅ |
| A03 Injection | `EntityManagerJpqlInjectionRule` | spring-boot | SQL_INJECTION_JPA | ✅ |
| A05 Config | `KafkaTrustedPackagesWildcardRule` | spring-boot | OBJECT_DESERIALIZATION | ✅ |
| A05 Config | `KafkaInsecureProtocolRule` | spring-boot | — | ✅ |
| A05 Config | `SpringSecurityDebugEnabledRule` | spring-boot | — | ✅ |
| A05 Config | `H2ConsoleEnabledRule` | spring-boot | — | ✅ |
| A07 Auth | `InsecureRememberMeRule` | spring-boot | HARD_CODE_PASSWORD | ✅ |
| A09 Logging | `ShowSqlEnabledRule` | spring-boot | INFORMATION_EXPOSURE | ✅ |
| A10 SSRF | `RestTemplateSsrfRule` | spring-boot | URLCONNECTION_SSRF_FD | ✅ |

---

## Adding a new rule

Use the `/add-security-rule` skill. It:
1. Fetches live FindSecBugs / OWASP docs
2. Decides which module the rule belongs in (`core`, `spring-boot`, `dropwizard`)
3. Adds patterns to `DetectionPatterns.kt`
4. Creates the rule class in the correct `a0X/` package
5. Creates the test class with positive, negative, and isolation tests
6. Registers the rule in the module's `*RuleSetProvider` and `detekt.yml`
7. Updates this coverage table

---

## Running

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21

./gradlew test          # all rule unit tests (core + spring-boot + dropwizard)
./gradlew detekt        # security scan of this repo
./gradlew test detekt   # both
```

Reports:
- `scanner-core/build/reports/detekt/`
- `scanner-spring-boot/build/reports/detekt/`
- `scanner-dropwizard/build/reports/detekt/`

---

## Testing rules

Each rule has a test class in the matching `a0X/` package with three layers:

```kotlin
// Positive — must be flagged
@Test fun `flags <vulnerable pattern>`()

// Negative — must NOT be flagged (safe equivalent)
@Test fun `ignores <safe pattern>`()

// Isolation — fixture from another rule must produce zero findings here
@Test fun `does not interfere with <other rule> code`()
```

Uses `io.gitlab.arturbosch.detekt:detekt-test` with `rule.lint(code)` and
`assertThat(findings)` from `assertj-core`.

---

## Using the scanner in your project

### Single-framework projects

**Spring Boot:**
```kotlin
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-spring-boot:0.2.0")
```

**Quarkus:**
```kotlin
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-quarkus:0.2.0")
```

**Ktor:**
```kotlin
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-ktor:0.2.0")
```

**Dropwizard:**
```kotlin
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-dropwizard:0.2.0")
```

**Micronaut:**
```kotlin
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-micronaut:0.2.0")
```

**Everything (convenience bundle):**
```kotlin
detektPlugins("io.github.jasminguberinic:scanner-all:0.2.0")
```

---

### Mixing framework modules (polyglot / multi-module projects)

Each module registers an independent Detekt rule set with a unique ID
(`security-core`, `security-ktor`, `security-quarkus`, …). Detekt runs every
loaded rule set against every Kotlin file, so **you can combine any number of
modules** by adding more `detektPlugins` entries — no conflicts, no duplicates.

**Typical combinations:**

```kotlin
// Dropwizard service that also uses Ktor for outbound HTTP clients
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-dropwizard:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-ktor:0.2.0")

// Quarkus monorepo with a Spring Boot admin module
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-quarkus:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-spring-boot:0.2.0")

// Migrating from Spring Boot to Micronaut — scan both during transition
detektPlugins("io.github.jasminguberinic:scanner-core:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-spring-boot:0.2.0")
detektPlugins("io.github.jasminguberinic:scanner-micronaut:0.2.0")
```

**Rules by scope:**

| Scope | Module | Examples |
|---|---|---|
| Any Kotlin code | `scanner-core` | Weak ciphers, hardcoded secrets, SQL injection, path traversal |
| Framework-agnostic HTTP | `scanner-core` | JAX-RS open redirect, CORS wildcard, JWT hardcoded key |
| Spring Boot–specific | `scanner-spring-boot` | `@GetMapping` without `@PreAuthorize`, CSRF disabled, SpEL injection |
| Quarkus–specific | `scanner-quarkus` | `@GET` without `@RolesAllowed`, Panache raw query, OIDC misconfiguration |
| Dropwizard–specific | `scanner-dropwizard` | JAX-RS missing `@Auth`, JDBI injection, insecure multipart |
| Ktor–specific | `scanner-ktor` | Missing `authenticate {}`, insecure cookie session, SSL redirect missing |
| Micronaut–specific | `scanner-micronaut` | `@Get` without `@Secured`, `@Client("http://")`, `@Body: Any` |

> **Note:** `scanner-core` is always required — all framework modules depend on it.
> `scanner-all` is a convenience bundle that includes every module; use it when you
> want maximum coverage without managing individual dependencies.

---

## CI

GitHub Actions runs `./gradlew test detekt` on every push and PR.
SARIF results are uploaded to GitHub Code Scanning for annotation
directly on PR diffs.

See `.github/workflows/ci.yml`.

---

## Community contribution

1. Fork the repo
2. Run `/add-security-rule` — the skill guides every step
3. Submit PR with `./gradlew test detekt` passing clean
4. Reference the FindSecBugs pattern ID in the PR description

See `.claude/commands/add-security-rule.md` for the full checklist.

---

## SSH / new machine setup

```bash
ssh-keygen -t ed25519 -C "jasmin.guberinic@gmail.com" \
  -f ~/.ssh/id_ed25519_personal -N ""

# Add to ~/.ssh/config:
# Host github.com-personal
#   HostName github.com
#   User git
#   IdentityFile ~/.ssh/id_ed25519_personal

# Add public key to: github.com/settings/ssh/new

git clone git@github.com-personal:JasminGuberinic/kotlin-security-scanner.git
```

## Stack

| Component | Version |
|---|---|
| Kotlin | 2.0.10 |
| Detekt | 1.23.7 |
| Java | 21 |
| Gradle | 8.x |
| AssertJ | 3.26.3 |
