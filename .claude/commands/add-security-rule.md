# Add Security Rule

**AI-driven workflow** for adding a new Detekt security rule.
Before writing any code, Claude fetches live documentation to ensure
the rule matches a real-world vulnerability pattern.

## Usage

```
/add-security-rule <RuleName> "<description>" <A0X>
```

Example:
```
/add-security-rule InsecureDeserializationRule "Flags ObjectInputStream.readObject on untrusted data" A08
```

---

## Step 1 — Research (always do this first)

Fetch the FindSecBugs pattern for this vulnerability type:
- `https://find-sec-bugs.github.io/bugs.htm` — look up the Bug Pattern ID
- `https://owasp.org/Top10/2021/` — confirm the OWASP category

Confirm the rule doesn't already exist in `DetectionPatterns.kt` or any `a0X/` package.

---

## Step 2 — Add patterns to `DetectionPatterns.kt`

Add any new constants to `src/main/kotlin/com/jasmin/security/detekt/core/DetectionPatterns.kt`
under the correct OWASP section comment. No detection logic goes here — only raw data.

```kotlin
// ── A08 Software and Data Integrity ───────────────────────────────────────────
val UNSAFE_DESERIALIZERS = setOf("ObjectInputStream", "XMLDecoder")
```

---

## Step 3 — Create the rule class

File: `src/main/kotlin/com/jasmin/security/detekt/a0X/<RuleName>.kt`

```kotlin
package com.jasmin.security.detekt.a0X

import com.jasmin.security.detekt.core.DetectionPatterns.<PATTERN>
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.*
import org.jetbrains.kotlin.psi.<PsiType>

// FindSecBugs: <BUG_PATTERN_ID> — OWASP A0X
class <RuleName>(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "<RuleName without 'Rule' suffix>",
        severity = Severity.Security,
        description = "<what is dangerous and what to use instead>",
        debt = Debt.TWENTY_MINS
    )

    // Keep each method to one concern.
    // Detection logic: visitXxx → guard clauses → named private predicate → reportAt
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        // ...
    }

    private fun isVulnerablePattern(expression: KtCallExpression): Boolean {
        // named predicate — reads like prose
    }
}
```

**Code style rules (enforced by Detekt itself):**
- `@Suppress("ReturnCount")` on any function with > 2 early returns
- Numeric constants go in `companion object`, not inline
- No cross-rule imports — only import from `core/`
- Max ~40 lines per rule file; extract private predicates if longer

---

## Step 4 — Create the test class

File: `src/test/kotlin/com/jasmin/security/detekt/a0X/<RuleName>Test.kt`

**Required test structure:**

```kotlin
package com.jasmin.security.detekt.a0X

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class <RuleName>Test {

    private val rule = <RuleName>()

    // POSITIVE — at least 3 variants of the vulnerability
    @Test fun `flags <variant 1>`() { ... }
    @Test fun `flags <variant 2>`() { ... }
    @Test fun `flags <variant 3>`() { ... }

    // NEGATIVE — safe equivalents that must NOT be flagged
    @Test fun `ignores <safe pattern 1>`() { ... }
    @Test fun `ignores <safe pattern 2>`() { ... }

    // ISOLATION — copy a positive fixture from a DIFFERENT rule and assert empty
    @Test fun `does not interfere with <other rule> code`() { ... }
}
```

---

## Step 5 — Register the rule

In `SecurityRuleSetProvider.kt`, add under the correct OWASP comment:

```kotlin
<RuleName>(config.subConfig("<RuleId>")),
```

In `config/detekt/detekt.yml` under `security-custom:`:

```yaml
  # A0X <OWASP Category>
  <RuleId>:
    active: true
```

---

## Step 6 — Update coverage map

In `CLAUDE.md`, update the OWASP coverage table: change TODO → ✅.

---

## Step 7 — Verify

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

Both must pass with zero new failures. `detekt` finding its own rule
files is a rule isolation bug — fix by adjusting detection logic or
adding an `excludes` pattern in `detekt.yml`.

---

## Community contribution checklist

Before submitting a PR:
- [ ] FindSecBugs pattern ID referenced in the rule comment
- [ ] OWASP category correct and in the right `a0X/` package
- [ ] Pattern constants added to `DetectionPatterns.kt`
- [ ] `SecurityRule` base class used (not raw `Rule`)
- [ ] Positive, negative, and isolation tests present
- [ ] CLAUDE.md coverage table updated
- [ ] `./gradlew test detekt` passes clean
