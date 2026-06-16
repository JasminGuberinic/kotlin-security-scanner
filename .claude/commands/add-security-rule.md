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

## Backlog — Phase 2 rules (pre-researched, ready to implement)

All rules below are verified absent from free Kotlin security tools. Full detection notes in `RULES_BACKLOG.md`.
Pick from Priority 1 first — those are unique to this tool. Properties-file rules (Priority 2) need `FileProcessListener`.

### Priority 1 — Unique (Kotlin-only, PSI-based)

| Rule | Module | OWASP | Key pattern |
|------|--------|-------|-------------|
| `CoroutineSecurityContextLossRule` | spring-boot | A01 | `visitNamedFunction` → `annotationNames()` contains "PreAuthorize"/"PostAuthorize" + function has `suspend` modifier (`modifierList?.hasModifier(KtTokens.SUSPEND_KEYWORD) == true`) |
| `ThymeleafSSTIRule` | spring-boot | A03 | `visitNamedFunction` → has `@GetMapping`/`@PostMapping`/`@RequestMapping` + return type is `String` + body contains string `+` or interpolation with `@RequestParam`/`@PathVariable` param names |
| `JacksonUnsafeDeserializationRule` | core | A08 | `visitCallExpression` callee in `setOf("enableDefaultTyping","activateDefaultTyping")` → flag always. Also `visitAnnotationEntry` shortName == "JsonTypeInfo" + `literalArg("use")` == "Id.CLASS" |
| `JwtNoneAlgorithmRule` | core | A02 | `visitCallExpression` callee == "signWith" + first arg text contains "NONE"; OR callee == "none" + `receiverText()` ends with "Algorithm" |
| `QuarkusJsonBeforeAuthRule` | quarkus | A01 | `visitClass` → has `@Path` + no class-level `@RolesAllowed`/`@Authenticated` + has method with body param (not annotated) |

### Priority 2 — Properties-file scanning

**Different approach — NOT a `Rule` subclass. Use `FileProcessListener`:**

```kotlin
class InsecureActuatorExposureListener : FileProcessListener {
    override fun onProcess(file: KtFile, bindingContext: BindingContext) {
        // Only process .properties / .yml files
        // Check raw file.text for the bad pattern
    }
}
```
Register in: `META-INF/services/io.gitlab.arturbosch.detekt.api.FileProcessListener`

| Rule | Module | OWASP | Property key to scan |
|------|--------|-------|---------------------|
| `InsecureActuatorExposureRule` | spring-boot | A05 | `management.endpoints.web.exposure.include` value == `*` |
| `QuarkusBuildTimeSecretLeakRule` | quarkus | A05 | key matches `*password*`/`*secret*`/`*token*` + value NOT `${...}` in `%prod` section |
| `QuarkusOidcInsecureConfigRule` | quarkus | A07 | `quarkus.oidc.token.issuer=any` or missing `quarkus.oidc.auth-server-url` |
| `InsecureSmtpConfigRule` | spring-boot | A02 | `spring.mail.properties.mail.smtp.starttls.enable=false` |

### Priority 3 — Coverage gaps

| Rule | Module | OWASP | Key pattern |
|------|--------|-------|-------------|
| `JwtWeakSecretRule` | core | A02 | `visitCallExpression` callee in `setOf("HMAC256","HMAC384","HMAC512","signWith")` + arg `firstArgIsLiteral()` |
| `WebClientSSRFRule` | spring-boot | A10 | callee == "create"/"uri" + `receiverText()` contains "WebClient" + arg NOT literal |
| `SpringDataMongoInjectionRule` | spring-boot | A03 | callee == "where" + `receiverText()` contains "Criteria" + arg non-literal |
| `DropwizardSelfValidatingELRule` | dropwizard | A03 | callee == "buildConstraintViolationWithTemplate" + arg non-literal |
| `MissingHttpsRedirectRule` | spring-boot | A02 | `visitNamedFunction` → `@Bean` + return type `SecurityFilterChain` + body does NOT contain "requiresChannel"/"requiresSecure" |
| `InsecureRedisConnectionRule` | spring-boot | A02 | callee == "RedisStandaloneConfiguration"/"LettuceConnectionFactory" → flag unless chained `.useSsl(true)` found |
| `UnsafeCryptoPaddingOracleRule` | core | A02 | callee == "getInstance" + arg literal == "AES/CBC/PKCS5Padding" → flag always (use GCM instead) |
| `RegexDenialOfServiceRule` | core | A06 | callee == "Regex"/"toRegex" + literal arg matches `\(.*\+\).*\+` or `\(\[.*\]\*\).*` ReDoS patterns |
| `XmlMapperUnsafeRule` | core | A08 | callee == "XmlMapper" (constructor call, no receiver) → flag always |
| `InsecurePasswordStorageRule` | core | A02 | callee == "getInstance"/"sha256Hex" + receiver/callee context near "password"/"passwd" variable → flag |
| `DropwizardUnencryptedJwtSecretRule` | dropwizard | A02 | callee == "setSecretProvider" + arg `firstArgIsLiteral()` |

---

## New PSI patterns for Phase 2 rules

### Check for `suspend` modifier on a function
```kotlin
override fun visitNamedFunction(function: KtNamedFunction) {
    super.visitNamedFunction(function)
    if (!function.hasModifier(KtTokens.SUSPEND_KEYWORD)) return
    val annotations = function.annotationNames()
    if ("PreAuthorize" !in annotations && "PostAuthorize" !in annotations) return
    reportAt(function, "...")
}
// Import: import org.jetbrains.kotlin.lexer.KtTokens
```

### Check annotations on a class (vs method)
```kotlin
override fun visitClass(klass: KtClass) {
    super.visitClass(klass)
    val classAnnotations = klass.annotationEntries
        .mapNotNull { it.shortName?.asString() }.toSet()
    val methodAnnotations = klass.declarations
        .filterIsInstance<KtNamedFunction>()
        .flatMap { it.annotationEntries }
        .mapNotNull { it.shortName?.asString() }.toSet()
}
```

### Detect absence of a call in a function body
```kotlin
override fun visitNamedFunction(function: KtNamedFunction) {
    super.visitNamedFunction(function)
    if ("Bean" !in function.annotationNames()) return
    val bodyText = function.bodyExpression?.text ?: return
    if ("requiresChannel" in bodyText || "requiresSecure" in bodyText) return
    reportAt(function, "SecurityFilterChain missing HTTPS redirect enforcement")
}
```

### visitAnnotationEntry (for @JsonTypeInfo check)
```kotlin
override fun visitAnnotationEntry(annotationEntry: KtAnnotationEntry) {
    super.visitAnnotationEntry(annotationEntry)
    if (annotationEntry.shortName?.asString() != "JsonTypeInfo") return
    val useArg = annotationEntry.literalArg("use") ?: return
    if ("CLASS" in useArg || "MINIMAL_CLASS" in useArg) {
        reportAt(annotationEntry, "...")
    }
}
// Import: import org.jetbrains.kotlin.psi.KtAnnotationEntry
```
