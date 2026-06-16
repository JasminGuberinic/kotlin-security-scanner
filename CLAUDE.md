# kotlin-security-scanner

Detekt plugin that detects OWASP Top 10 security vulnerabilities in
Kotlin Spring Boot applications at compile time.

Designed to grow: every rule follows the same architecture so contributors
(human or AI) can add new coverage without touching existing rules.

---

## Architecture

```
src/main/kotlin/com/jasmin/security/detekt/
│
├── core/
│   ├── SecurityRule.kt          # Base class — shared AST helpers & reporting
│   └── DetectionPatterns.kt     # All detection patterns, grouped by OWASP
│
├── a01/  MissingAuthorizationRule
├── a02/  WeakCipherModeRule
├── a03/  SqlInjectionRule · PathTraversalRule
├── a05/  SpringCsrfDisabledRule · PermissiveCorsRule
├── a07/  HardcodedCredentialsRule · InsecureRandomRule
├── a09/  SensitiveDataLoggingRule
├── a10/  SsrfRule
│
└── SecurityRuleSetProvider.kt   # SPI entry — register new rules here

src/test/kotlin/com/jasmin/security/detekt/
└── a01/ a02/ a03/ a05/ a07/ a09/ a10/  # mirrors main — one test file per rule

config/detekt/detekt.yml         # Detekt config with built-in + custom rules
src/main/kotlin/.../example/     # VulnerableExamples.kt — intentional findings
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

| OWASP 2021 | Rule | FindSecBugs ID | Status |
|---|---|---|---|
| A01 Broken Access Control | `MissingAuthorizationRule` | SPRING_ENDPOINT | ✅ |
| A02 Cryptographic Failures | `WeakCipherModeRule` + `ForbiddenMethodCall` (MD5/SHA1) | ECB_MODE, DES_USAGE | ✅ |
| A03 Injection — SQL | `SqlInjectionRule` | SQL_INJECTION_JPA | ✅ |
| A03 Injection — Path Traversal | `PathTraversalRule` | PATH_TRAVERSAL_IN | ✅ |
| A03 Injection — Command | `ForbiddenImport` (Runtime) | COMMAND_INJECTION | ✅ partial |
| A05 CSRF | `SpringCsrfDisabledRule` | SPRING_CSRF_PROTECTION_DISABLED | ✅ |
| A05 CORS | `PermissiveCorsRule` | PERMISSIVE_CORS | ✅ |
| A07 Hardcoded Secrets | `HardcodedCredentialsRule` | HARD_CODE_PASSWORD | ✅ |
| A07 Insecure Random | `InsecureRandomRule` + `ForbiddenImport` (Random) | PREDICTABLE_RANDOM | ✅ |
| A09 Sensitive Logging | `SensitiveDataLoggingRule` | INFORMATION_EXPOSURE | ✅ |
| A10 SSRF | `SsrfRule` | URLCONNECTION_SSRF_FD | ✅ |
| A04 Insecure Design | — | — | TODO |
| A06 Vulnerable Components | — | — | TODO |
| A08 Deserialization | `InsecureDeserializationRule` | OBJECT_DESERIALIZATION | TODO |

---

## Adding a new rule

Use the `/add-security-rule` skill. It:
1. Fetches live FindSecBugs / OWASP docs
2. Adds patterns to `DetectionPatterns.kt`
3. Creates the rule class in the correct `a0X/` package
4. Creates the test class with positive, negative, and isolation tests
5. Registers the rule in `SecurityRuleSetProvider` and `detekt.yml`
6. Updates this coverage table

---

## Running

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21

./gradlew test          # rule unit tests
./gradlew detekt        # security scan of this repo
./gradlew test detekt   # both
```

Reports: `build/reports/detekt/detekt.html` · `.xml` · `.sarif`

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

Uses `io.gitlab.arturbosch.detekt:detekt-test` with `rule.lint(code)` and `assertThat(findings)`.

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
| Spring Boot | 3.5.0 |
| Detekt | 1.23.7 |
| Java | 21 |
| Gradle | 8.x |
