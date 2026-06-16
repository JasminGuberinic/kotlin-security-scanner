package com.jasmin.security.detekt.a06

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
 * OWASP A06 — Vulnerable and Outdated Components
 * FindSecBugs: REDOS
 *
 * Regular expressions with catastrophic backtracking can be exploited to
 * cause CPU exhaustion. Patterns like (a+)+, ([a-z]+)*, (a|aa)+ have
 * exponential worst-case matching time against crafted inputs.
 *
 * Compliant:
 *   Regex("[a-z]+")
 *   Regex("^[0-9]{1,10}$")
 *
 * Non-compliant:
 *   Regex("(a+)+")
 *   "(\\w+\\.)+\\w+".toRegex()
 */
class RegexDenialOfServiceRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "RegexDenialOfService",
        severity = Severity.Security,
        description = "Regex pattern with catastrophic backtracking — rewrite to avoid nested quantifiers",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.REGEX_CONSTRUCTORS) return
        val literal = resolvePatternLiteral(expression, callee) ?: return
        if (literal.hasInterpolation()) return
        val pattern = literal.text.removeSurrounding("\"")
        if (DetectionPatterns.REDOS_PATTERNS.none { it.containsMatchIn(pattern) }) return
        reportAt(expression, "Regex pattern with nested quantifiers — vulnerable to ReDoS attack")
    }

    private fun resolvePatternLiteral(
        expression: KtCallExpression,
        callee: String,
    ): KtStringTemplateExpression? = when (callee) {
        "toRegex" -> (expression.parent as? KtDotQualifiedExpression)
            ?.receiverExpression as? KtStringTemplateExpression
        else -> expression.valueArguments.firstOrNull()
            ?.getArgumentExpression() as? KtStringTemplateExpression
    }
}
