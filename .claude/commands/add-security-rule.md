# Add Security Rule

Creates a new Detekt security rule for Kotlin/Spring Boot vulnerability detection.

## Usage

```
/add-security-rule <RuleName> "<short description>" <OWASP-category>
```

Example:
```
/add-security-rule SsrfRule "Detects server-side request forgery via user-controlled URLs" A10
```

## Steps to execute

**Before writing any code**, fetch the latest FindSecBugs documentation for the vulnerability type:
- https://find-sec-bugs.github.io/bugs.htm — look up the specific bug pattern ID
- Check `CLAUDE.md` OWASP coverage map to avoid duplicating existing rules

**1. Create the rule class** at `src/main/kotlin/com/jasmin/security/detekt/<RuleName>.kt`:

```kotlin
package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.*
import org.jetbrains.kotlin.psi.<RelevantPsiType>

class <RuleName>(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "<RuleName>",
        severity = Severity.Security,
        description = "<description — what is vulnerable and what to use instead>",
        debt = Debt.TWENTY_MINS
    )

    companion object {
        // Extract any numeric constants here (avoids MagicNumber rule)
    }

    override fun visit<PsiNode>(node: <PsiNode>) {
        super.visit<PsiNode>(node)
        // Detection logic
        // report(CodeSmell(issue, Entity.from(node), "message"))
    }
}
```

**2. Create the test class** at `src/test/kotlin/com/jasmin/security/detekt/<RuleName>Test.kt`:

```kotlin
package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.test.lint
import io.gitlab.arturbosch.detekt.test.assertThat
import org.junit.jupiter.api.Test

class <RuleName>Test {

    private val rule = <RuleName>()

    // POSITIVE TESTS — code that MUST be flagged
    @Test
    fun `flags <vulnerable pattern description>`() {
        val code = """
            <minimal code that triggers the rule>
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // Add at least 2-3 positive test cases covering different forms of the vulnerability

    // NEGATIVE TESTS — safe code that must NOT be flagged
    @Test
    fun `ignores <safe pattern description>`() {
        val code = """
            <safe equivalent code>
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Add at least 2 negative test cases

    // ISOLATION TEST — rule must not flag code from OTHER rules' test fixtures
    @Test
    fun `does not flag unrelated code`() {
        val code = """
            <copy a positive test fixture from a DIFFERENT rule>
        """.trimIndent()
        // This rule should NOT find the other rule's vulnerability
        // (verify they are truly independent)
        assertThat(rule.lint(code)).isEmpty()
    }
}
```

**3. Register in `SecurityRuleSetProvider.kt`** — add to the `listOf(...)`:
```kotlin
<RuleName>(config.subConfig("<RuleName>")),
```

**4. Add to `config/detekt/detekt.yml`** under `security-custom:`:
```yaml
  <RuleName>:
    active: true
```

**5. Add to `VulnerableExamples.kt`** — add a commented example showing what gets caught.

**6. Update `CLAUDE.md`** OWASP coverage map — mark the rule as ✅.

**7. Run validation**:
```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

Both must pass. If `detekt` fails due to the new rule flagging itself or existing code, that is a rule isolation bug — fix it by adjusting the rule's detection logic or adding `excludes` in the config.

## Key constraints (always follow)

- **No circular detection**: A rule must never flag code in another rule's implementation file. Detekt rule files live in `com.jasmin.security.detekt` — add package-level excludes if needed.
- **Positive + negative tests**: Every rule needs both. A rule with only positive tests may have false positives in production.
- **FindSecBugs alignment**: Map each rule to a FindSecBugs bug pattern ID in the rule's `issue.description`.
- **`companion object` for constants**: Numeric literals in rule logic go in `companion object` to avoid triggering `MagicNumber`.
- **No cross-imports between rules**: Rules must compile independently.
