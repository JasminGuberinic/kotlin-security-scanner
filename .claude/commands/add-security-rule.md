# Add Security Rule

Token-efficient workflow. All research is in `RULES_BACKLOG.md` — do NOT fetch external docs.
Pick a rule from the backlog, run this skill, mark the checkbox.

## Usage

```
/add-security-rule <RuleName> <module> <A0X>
```

Example: `/add-security-rule CommandInjectionRule core A03`

Modules: `core` | `spring-boot` | `dropwizard` | `quarkus`

---

## Before writing anything

1. Read `RULES_BACKLOG.md` — find the row for this rule, copy Detection target + FindSecBugs ID
2. Check the rule doesn't already exist: `grep -r "<RuleName>" scanner-*/src/`
3. Note which module → maps to `scanner-<module>/src/main/kotlin/com/jasmin/security/detekt/`

Module → Provider mapping:
- `core` → `CoreRuleSetProvider.kt`, ruleSetId `security-core`
- `spring-boot` → `SpringBootRuleSetProvider.kt`, ruleSetId `security-spring-boot`
- `dropwizard` → `DropwizardRuleSetProvider.kt`, ruleSetId `security-dropwizard`
- `quarkus` → `QuarkusRuleSetProvider.kt`, ruleSetId `security-quarkus`

---

## Step 1 — Patterns (only if new pattern needed)

Add to `scanner-core/src/main/kotlin/com/jasmin/security/detekt/core/DetectionPatterns.kt`
under the correct `// ── A0X …` comment. One line per entry, trailing comma.

Skip this step if the pattern already exists.

---

## Step 2 — Rule class

Path: `scanner-<module>/src/main/kotlin/com/jasmin/security/detekt/a0X/<RuleName>.kt`

```kotlin
package com.jasmin.security.detekt.a0X

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.<PsiVisitType>

/**
 * OWASP A0X — <Category Name>
 * FindSecBugs: <BUG_PATTERN_ID>
 *
 * <One line: what is dangerous.>
 *
 * Compliant:
 *   <safe code example>
 *
 * Non-compliant:
 *   <vulnerable code example>
 */
class <RuleName>(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "<RuleId>",
        severity = Severity.Security,
        description = "<short description — max 120 chars>",
        debt = Debt.TWENTY_MINS,
    )

    override fun visit<PsiType>(expression: <KtPsiType>) {
        super.visit<PsiType>(expression)
        if (!<isVulnerablePattern>(expression)) return
        reportAt(expression, "<message explaining risk and fix>")
    }

    private fun <isVulnerablePattern>(expression: <KtPsiType>): Boolean {
        // guard clauses: return false for safe patterns
        // last line: return true
    }
}
```

**Rules:**
- `@Suppress("ReturnCount")` if function has > 2 early returns
- Numeric constants → `companion object { private const val X = n }`
- Only import from `core/` — never cross-rule imports
- `visitCallExpression` for method calls, `visitNamedFunction` for annotations, `visitProperty` for field annotations

---

## Step 3 — Test class

Path: `scanner-<module>/src/test/kotlin/com/jasmin/security/detekt/a0X/<RuleName>Test.kt`

```kotlin
package com.jasmin.security.detekt.a0X

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class <RuleName>Test {

    private val rule = <RuleName>(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test fun `flags <variant 1>`() {
        val code = """
            <minimal Kotlin snippet that triggers the rule>
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test fun `flags <variant 2>`() { ... }
    @Test fun `flags <variant 3>`() { ... }   // at least 3 variants

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test fun `ignores <safe pattern 1>`() {
        val code = """
            <safe equivalent — same structure but secure>
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test fun `ignores <safe pattern 2>`() { ... }

    // ── Isolation — zero findings on other rules' code ────────────────────────

    @Test fun `does not trigger on <other rule> fixture`() {
        // Copy a POSITIVE test from a DIFFERENT rule in the same module
        // Must return isEmpty()
    }
}
```

Minimum: 3 positive, 2 negative, 1 isolation.

---

## Step 4 — Register

**Provider** (`scanner-<module>/src/main/kotlin/com/jasmin/security/detekt/<Module>RuleSetProvider.kt`):
```kotlin
// A0X <Category>
<RuleName>(config.subConfig("<RuleId>")),
```

**detekt.yml** (`config/detekt/detekt.yml`) under `security-<module>:`:
```yaml
  # A0X <Category>
  <RuleId>:
    active: true
```

---

## Step 5 — Update backlog + CLAUDE.md

- Mark `[x]` in `RULES_BACKLOG.md` for this rule
- Add row to OWASP coverage table in `CLAUDE.md` with ✅

---

## Step 6 — Verify

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

Zero new failures. If detekt flags its own rule file, tighten detection logic.

---

## Common PSI patterns (copy-paste reference)

```kotlin
// Is first argument a string literal?
fun KtCallExpression.firstArgIsLiteral() =
    valueArguments.firstOrNull()?.getArgumentExpression()
        ?.let { it is KtStringTemplateExpression && !it.hasInterpolation() } == true

// Is any argument non-literal (variable/expression)?
fun KtCallExpression.hasNonLiteralArg() =
    valueArguments.any { arg ->
        val e = arg.getArgumentExpression()
        e !is KtStringTemplateExpression || e.hasInterpolation()
    }

// Get receiver name (e.g. "Runtime" from Runtime.getRuntime().exec(...))
fun KtCallExpression.receiverText() = (parent as? KtDotQualifiedExpression)
    ?.receiverExpression?.text

// Callee name
val KtCallExpression.calleeName get() = calleeExpression?.text
```
