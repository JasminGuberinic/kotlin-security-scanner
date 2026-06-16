package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (Reflection)
 * FindSecBugs: REFLECTOR_BASED_INJECTION
 *
 * Flags Class.forName() calls where the class name is not a string literal.
 * Loading an attacker-supplied class name enables deserialization gadget injection,
 * unexpected code execution, or classpath enumeration.
 *
 * Compliant:
 *   Class.forName("com.example.SomeService")     // literal — safe
 *
 * Non-compliant:
 *   Class.forName(className)                      // variable — attacker-chosen class
 *   Class.forName("com.${'$'}userInput")          // interpolated — partial control
 */
class ReflectionInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ReflectionInjection",
        severity = Severity.Security,
        description = "Class.forName() with non-literal class name — attacker-controlled class loading",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.CLASS_FOR_NAME_METHOD) return
        val parentDot = expression.parent as? KtDotQualifiedExpression ?: return
        if (!parentDot.receiverExpression.text.endsWith(DetectionPatterns.CLASS_FOR_NAME_RECEIVER)) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (!isSafe) {
            reportAt(
                expression,
                "Class.forName() with dynamic class name — use a hardcoded allowlist of permitted class names",
            )
        }
    }
}
