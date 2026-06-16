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
 * OWASP A03 — Injection (NoSQL)
 * FindSecBugs: SQL_INJECTION_JPA (closest analog)
 *
 * Criteria.where(field) with a non-literal field name allows an attacker
 * to manipulate the MongoDB query structure, bypassing intended filters.
 *
 * Compliant:
 *   Criteria.where("username").is(value)
 *
 * Non-compliant:
 *   Criteria.where(userSuppliedField).is(value)
 */
class SpringDataMongoInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringDataMongoInjection",
        severity = Severity.Security,
        description = "Criteria.where() with dynamic field name — use a literal field name to prevent NoSQL injection",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.MONGO_CRITERIA_WHERE) return
        val parentDot = expression.parent as? KtDotQualifiedExpression ?: return
        if (!parentDot.receiverExpression.text.contains(DetectionPatterns.MONGO_CRITERIA_CLASS)) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (isSafe) return
        reportAt(
            expression,
            "Criteria.where() with non-literal field — use a hardcoded field name string",
        )
    }
}
