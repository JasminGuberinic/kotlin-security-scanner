# kotlin-security-scanner

Detekt-based static analysis plugin for Kotlin Spring Boot applications.
Detects OWASP Top 10 vulnerabilities at compile time.

## Project structure

```
src/main/kotlin/com/jasmin/security/
├── detekt/          # Custom Detekt rule implementations
│   ├── SecurityRuleSetProvider.kt   # SPI entry point — register new rules here
│   ├── HardcodedCredentialsRule.kt
│   ├── SqlInjectionRule.kt
│   ├── InsecureRandomRule.kt
│   ├── SpringCsrfDisabledRule.kt
│   ├── WeakCipherModeRule.kt
│   ├── PathTraversalRule.kt
│   └── SensitiveDataLoggingRule.kt
└── example/
    └── VulnerableExamples.kt        # Demo: intentional findings

src/test/kotlin/com/jasmin/security/
└── detekt/          # One test class per rule — mirrors detekt/ package

config/detekt/detekt.yml             # Detekt config: built-in + custom rules
```

## Adding a new rule

Use the `/add-security-rule` skill. It will:
1. Create the rule class in `detekt/`
2. Create the test class in `detekt/` under test sources
3. Register the rule in `SecurityRuleSetProvider`
4. Add the rule section to `config/detekt/detekt.yml`
5. Run tests to verify no interference with existing rules

## Rule design constraints

- Each rule must have its own test file
- Rules must NOT trigger on each other's test fixtures
- Rules must NOT trigger on Detekt's own API classes (detekt package is excluded)
- Use `@Suppress("RuleName")` only in `VulnerableExamples.kt` and test fixtures
- `maxIssues` in detekt.yml covers production code; VulnerableExamples is allowed to have findings

## Testing approach

Uses `io.gitlab.arturbosch.detekt:detekt-test`. Each test:
- Tests the positive case (code THAT should be flagged)
- Tests the negative case (safe equivalent that should NOT be flagged)
- Asserts exact finding count, not just > 0

```kotlin
import io.gitlab.arturbosch.detekt.test.lint
import io.gitlab.arturbosch.detekt.test.assertThat

class MyRuleTest {
    private val rule = MyRule()

    @Test
    fun `flags vulnerable pattern`() {
        val code = "val password = \"secret\""
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores safe pattern`() {
        val code = "val password = \"\${env.PASSWORD}\""
        assertThat(rule.lint(code)).isEmpty()
    }
}
```

## OWASP coverage map

| OWASP 2021 | Rule | Status |
|---|---|---|
| A02 Cryptographic Failures | `WeakCipherModeRule`, `ForbiddenMethodCall` (MD5/SHA1), `ForbiddenImport` (DES) | ✅ |
| A03 Injection — SQL | `SqlInjectionRule` | ✅ |
| A03 Injection — Command | `ForbiddenImport` (Runtime) | ✅ partial |
| A03 Injection — Path Traversal | `PathTraversalRule` | ✅ |
| A05 Security Misconfiguration | `SpringCsrfDisabledRule` | ✅ |
| A07 Auth Failures — Secrets | `HardcodedCredentialsRule` | ✅ |
| A07 Auth Failures — Random | `InsecureRandomRule`, `ForbiddenImport` (Random) | ✅ |
| A09 Logging Failures | `SensitiveDataLoggingRule` | ✅ |
| A01 Broken Access Control | `MissingAuthorizationRule` | TODO |
| A10 SSRF | `SsrfRule` | TODO |

## Running the scanner

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew detekt                    # run scan
./gradlew detekt --continue         # don't stop on first failure
./gradlew test                      # run rule unit tests
```

Reports output to `build/reports/detekt/`:
- `detekt.html` — human readable
- `detekt.xml`  — CI integration (e.g. GitHub Actions)
- `detekt.sarif` — GitHub Code Scanning

## Stack

- Kotlin 2.0.10
- Spring Boot 3.5.0
- Detekt 1.23.7
- Java 21
- Gradle 8.x

## SSH / repo setup (new machine)

```bash
ssh-keygen -t ed25519 -C "jasmin.guberinic@gmail.com" -f ~/.ssh/id_ed25519_personal -N ""
# Add to ~/.ssh/config:
#   Host github.com-personal
#     HostName github.com
#     User git
#     IdentityFile ~/.ssh/id_ed25519_personal
# Add public key to github.com/settings/ssh/new
git clone git@github.com-personal:JasminGuberinic/kotlin-security-scanner.git
```
