package com.jasmin.security.detekt.a06

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A06 — Vulnerable and Outdated Components (Regular Expression DoS)
 *
 * Compiling a regular expression built from non-literal (potentially user-supplied)
 * input lets an attacker inject a catastrophically backtracking pattern, hanging the
 * thread (ReDoS). Treat user input as data to match against a fixed pattern — never
 * as the pattern itself.
 *
 * Compliant:
 *   Pattern.compile("^[a-z0-9]+$").matcher(userInput)
 *
 * Non-compliant:
 *   Pattern.compile(userInput)
 *   Regex(userPattern)
 *   userPattern.toRegex()
 */
class RegexInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "RegexInjection",
        severity = Severity.Security,
        description = "Regex compiled from non-literal input — an injected pattern can hang the thread (ReDoS)",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        val dynamic = when (callee) {
            DetectionPatterns.PATTERN_COMPILE_METHOD -> {
                val receiver = (expression.parent as? KtDotQualifiedExpression)
                    ?.receiverExpression?.text?.substringAfterLast(".")
                if (receiver != DetectionPatterns.PATTERN_CLASS) return
                expression.valueArguments.firstOrNull()?.getArgumentExpression()?.let { isDynamic(it) } ?: false
            }
            "Regex" ->
                expression.valueArguments.firstOrNull()?.getArgumentExpression()?.let { isDynamic(it) } ?: false
            "toRegex", "toPattern" ->
                (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.let { isDynamic(it) } ?: false
            else -> return
        }
        if (dynamic) {
            reportAt(
                expression,
                "Regex compiled from non-literal input — match user input against a fixed pattern instead",
            )
        }
    }

    private fun isDynamic(expr: KtExpression): Boolean {
        // A bare string literal is a KtStringTemplateExpression with no interpolation;
        // an interpolated template or any other expression (variable/call) is dynamic.
        if (expr is KtStringTemplateExpression) return expr.hasInterpolation()
        return true
    }
}
