# kotlin-security-scanner

Detekt plugin that detects OWASP Top 10 security vulnerabilities in
Kotlin applications at compile time — with module-level picks for
Spring Boot, Dropwizard, or any Kotlin project.

Designed to grow: every rule follows the same architecture so contributors
(human or AI) can add new coverage without touching existing rules.

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
| A01 Broken Access Control | `DropwizardMissingAuthRule` | dropwizard | JAXRS_ENDPOINT | ✅ |
| A02 Cryptographic Failures | `WeakCipherModeRule` + `ForbiddenMethodCall` (MD5/SHA1) | core | ECB_MODE, DES_USAGE | ✅ |
| A02 Cryptographic Failures | `InsecureTlsProtocolRule` | dropwizard | SSL_CONTEXT | ✅ |
| A03 Injection — SQL | `SqlInjectionRule` | core | SQL_INJECTION_JPA | ✅ |
| A03 Injection — Path Traversal | `PathTraversalRule` | core | PATH_TRAVERSAL_IN | ✅ |
| A03 Injection — Command | `ForbiddenImport` (Runtime) | core | COMMAND_INJECTION | ✅ partial |
| A05 CSRF | `SpringCsrfDisabledRule` | spring-boot | SPRING_CSRF_PROTECTION_DISABLED | ✅ |
| A05 CORS | `PermissiveCorsRule` | spring-boot | PERMISSIVE_CORS | ✅ |
| A07 Hardcoded Secrets | `HardcodedCredentialsRule` | core | HARD_CODE_PASSWORD | ✅ |
| A07 Insecure Random | `InsecureRandomRule` + `ForbiddenImport` | core | PREDICTABLE_RANDOM | ✅ |
| A09 Sensitive Logging | `SensitiveDataLoggingRule` | core | INFORMATION_EXPOSURE | ✅ |
| A10 SSRF | `SsrfRule` | core | URLCONNECTION_SSRF_FD | ✅ |
| A04 Insecure Design | — | — | — | TODO |
| A06 Vulnerable Components | — | — | — | TODO |
| A08 Deserialization | `InsecureDeserializationRule` | core | OBJECT_DESERIALIZATION | TODO |

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

**Spring Boot project:**
```kotlin
// build.gradle.kts
detektPlugins("com.jasmin.security:scanner-core:0.1.0-SNAPSHOT")
detektPlugins("com.jasmin.security:scanner-spring-boot:0.1.0-SNAPSHOT")
```

**Dropwizard project:**
```kotlin
detektPlugins("com.jasmin.security:scanner-core:0.1.0-SNAPSHOT")
detektPlugins("com.jasmin.security:scanner-dropwizard:0.1.0-SNAPSHOT")
```

**Everything:**
```kotlin
detektPlugins("com.jasmin.security:scanner-all:0.1.0-SNAPSHOT")
```

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
