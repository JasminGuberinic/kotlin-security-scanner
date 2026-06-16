# Add Security Rule

Token-efficient workflow. All research is pre-embedded below — do NOT fetch external docs.
Pick a rule from the backlog table at the bottom, implement it, mark the checkbox in `RULES_BACKLOG.md`.

## Usage

```
/add-security-rule <RuleName> <module> <A0X>
```

Example: `/add-security-rule WeakRsaKeyRule core A02`

Modules: `core` | `spring-boot` | `dropwizard` | `quarkus`

---

## Before writing anything

1. Read `RULES_BACKLOG.md` — find the row, copy Detection target + FindSecBugs ID
2. Verify it doesn't exist: `grep -r "<RuleName>" scanner-*/src/`
3. Module → Provider + ruleSetId:
   - `core` → `CoreRuleSetProvider.kt` / `security-core`
   - `spring-boot` → `SpringBootRuleSetProvider.kt` / `security-spring-boot`
   - `dropwizard` → `DropwizardRuleSetProvider.kt` / `security-dropwizard`
   - `quarkus` → `QuarkusRuleSetProvider.kt` / `security-quarkus`

---

## Step 1 — Add patterns (only if new)

File: `scanner-core/src/main/kotlin/com/jasmin/security/detekt/core/DetectionPatterns.kt`

- Add under the correct `// ── A0X …` comment
- `const val` for a single string — required to avoid `MayBeConst` violation
- `val` for `setOf(...)` / `listOf(...)`
- Trailing comma on last element

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
import org.jetbrains.kotlin.psi.<KtPsiType>

/**
 * OWASP A0X — <Category>
 * FindSecBugs: <BUG_ID>
 *
 * <One sentence describing the vulnerability.>
 *
 * Compliant:
 *   <safe example — one line>
 *
 * Non-compliant:
 *   <vulnerable example — one line>
 */
class <RuleName>(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "<RuleId>",
        severity = Severity.Security,
        description = "<description — max 120 chars including indentation>",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")   // include if > 2 early returns
    override fun visit<PsiType>(expression: <KtPsiType>) {
        super.visit<PsiType>(expression)
        // Guard clauses first — return early for safe patterns
        reportAt(
            expression,
            "<message: what is wrong + how to fix>",
        )
    }
}
```

**Detekt formatting rules — violations will fail the build:**
- `@Suppress("ReturnCount")` on any function with > 2 explicit `return` statements
- `@Suppress("MagicNumber")` on any function using numeric literals in logic
- `reportAt(node, "msg")` on one line if total ≤ 120 chars; otherwise always 3 lines:
  ```kotlin
  reportAt(
      node,
      "message here",
  )
  ```
- String constants (`val FOO = "bar"`) → must be `const val FOO = "bar"` to avoid `MayBeConst`
- Max line length = 120 chars (count from column 1 including leading spaces)

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

    @Test
    fun `flags <variant 1>`() {
        val code = """
            <minimal Kotlin snippet — imports optional, body only>
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // minimum 3 positive tests

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores <safe pattern 1>`() {
        val code = """ <safe equivalent> """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // minimum 2 negative tests

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on <other rule> fixture`() {
        // Copy a POSITIVE snippet from a DIFFERENT rule in the same module.
        // This test must return isEmpty() to prove rules don't interfere.
        assertThat(rule.lint(code)).isEmpty()
    }
}
```

---

## Step 4 — Register

**Provider** (add import at the top, add entry in the rule list):
```kotlin
import com.jasmin.security.detekt.a0X.<RuleName>

// In instance():
<RuleName>(config.subConfig("<RuleId>")),
```

**`config/detekt/detekt.yml`** under `security-<module>:`:
```yaml
  # A0X <Category>
  <RuleId>:
    active: true
```

---

## Step 5 — Verify + update docs

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

Zero new failures. Then:
- Mark `[x]` for this rule in `RULES_BACKLOG.md`
- Add row to OWASP coverage table in `CLAUDE.md` with ✅

---

## PSI pitfalls — read this before coding

### Dot-qualified calls: callee text is the METHOD name only

```
Class.forName(name)          → visitCallExpression callee = "forName"
Runtime.getRuntime().exec()  → visitCallExpression callee = "exec"
ctx.lookup(name)             → visitCallExpression callee = "lookup"
```

To verify the receiver, check the parent node:
```kotlin
val parentDot = expression.parent as? KtDotQualifiedExpression ?: return
val receiver = parentDot.receiverExpression.text  // "Class", "ctx", etc.
// Use endsWith for qualified names: receiver.endsWith("Class")
```

### Annotation arguments — use `valueArgumentList?.arguments`, not `getValueArguments()`

```kotlin
// WRONG — getValueArguments() returns List<ValueArgument> (interface, .text unresolved)
annotation.getValueArguments().first().text   // compile error

// RIGHT — valueArgumentList?.arguments returns List<KtValueArgument> (.text works)
annotation.valueArgumentList?.arguments
    ?.firstOrNull { it.text.substringBefore("=").trim() == "name" }
    ?.getArgumentExpression() as? KtStringTemplateExpression
```

### Detecting literal vs interpolated string

```kotlin
// Safe (literal): KtStringTemplateExpression with no interpolation entries
val isSafe = arg is KtStringTemplateExpression && !arg.hasInterpolation()

// Unsafe (variable reference or interpolated): anything else
val isUnsafe = arg !is KtStringTemplateExpression || arg.hasInterpolation()
```

### visitCallExpression vs visitNamedFunction vs visitClass

| Goal | Override |
|------|----------|
| Detect a method call `foo(...)` | `visitCallExpression` |
| Detect annotation on a method `@Foo fun bar()` | `visitNamedFunction` |
| Detect annotation on a class `@Foo class Bar` | `visitClass` |
| Detect a property `val x = ...` | `visitProperty` |
| Detect string template `"hello $name"` | `visitStringTemplateExpression` |
| Detect binary expression `"a" + b` | `visitBinaryExpression` |

Detekt calls these for EVERY matching node in the file — no manual tree traversal needed.

---

## PSI quick-reference (copy-paste)

```kotlin
// Is first argument a literal string (no interpolation)?
fun KtCallExpression.firstArgIsLiteral() =
    valueArguments.firstOrNull()?.getArgumentExpression()
        ?.let { it is KtStringTemplateExpression && !it.hasInterpolation() } == true

// Does any argument contain non-literal content?
fun KtCallExpression.hasNonLiteralArg() =
    valueArguments.any { arg ->
        val e = arg.getArgumentExpression()
        e !is KtStringTemplateExpression || e.hasInterpolation()
    }

// Receiver text from dot-qualified parent
fun KtCallExpression.receiverText() =
    (parent as? KtDotQualifiedExpression)?.receiverExpression?.text

// Method name
val KtCallExpression.calleeName get() = calleeExpression?.text

// All annotation short-names on a function
fun KtNamedFunction.annotationNames() =
    annotationEntries.mapNotNull { it.shortName?.asString() }.toSet()

// Read a named annotation argument as a literal string
fun KtAnnotationEntry.literalArg(name: String): String? {
    val expr = valueArgumentList?.arguments
        ?.firstOrNull { it.text.substringBefore("=").trim() == name }
        ?.getArgumentExpression() as? KtStringTemplateExpression ?: return null
    if (expr.hasInterpolation()) return null
    return expr.text.removeSurrounding("\"")
}
```

---

## Backlog — next 5 rules (pre-researched, ready to implement)

| Rule | Module | OWASP | FindSecBugs | Detection pattern |
|------|--------|-------|-------------|-------------------|
| `WeakRsaKeyRule` | core | A02 | BLOWFISH_KEY_SIZE, RSA_KEY_SIZE | `callee == "initialize"` + first arg is `KtConstantExpression` ≤ 1024; add `@Suppress("MagicNumber")`. Add `const val KEY_GEN_INIT = "initialize"` to patterns. |
| `GroovyScriptInjectionRule` | core | A03 | GROOVY_SHELL | `callee == "evaluate"` + arg is non-literal; OR `callee == "eval"` + receiver contains "ScriptEngine". Add `val SCRIPT_EVAL_METHODS = setOf("evaluate", "eval")`. |
| `ELInjectionRule` | spring-boot | A03 | EL_INJECTION | `callee == "eval"` + receiver ends with "ELProcessor"; OR `callee == "createValueExpression"` + first arg non-literal. Add `val EL_EVAL_METHODS = setOf("eval", "createValueExpression")`. |
| `CsrfTokenLeakRule` | spring-boot | A01 | SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING | `callee == "addAttribute"` + first arg literal containing "csrf" or "token" + second arg non-literal. Flag when CSRF token is exposed in model attributes. Add `val CSRF_TOKEN_KEYWORDS = setOf("csrf", "_csrf", "csrfToken")`. |
| `QuarkusUnsafeHeaderRule` | quarkus | A05 | HTTP_RESPONSE_SPLITTING | `callee == "header"` + second arg is non-literal; scoped to JAX-RS `Response` builder chain — check receiver text contains "Response" or parent is dot-qualified expression. Reuse `HTTP_HEADER_SETTER_METHODS` from core DetectionPatterns. |
