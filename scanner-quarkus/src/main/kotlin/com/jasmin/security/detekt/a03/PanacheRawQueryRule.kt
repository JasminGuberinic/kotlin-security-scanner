package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (SQL via Panache)
 * FindSecBugs: SQL_INJECTION_JPA
 *
 * Flags Panache query methods (find, list, count, delete, update) called with an
 * interpolated string as the first argument. Panache passes the string directly to
 * the JPA query engine — user input in that string enables SQL/HQL injection.
 *
 * Compliant:
 *   User.find("name = ?1", name)              // positional parameter
 *   User.find("name", name)                   // shorthand field match
 *
 * Non-compliant:
 *   User.find("name = '${'$'}name'")          // interpolated — SQL injection
 *   User.list("role = '${'$'}{userRole}'")    // interpolated — SQL injection
 */
class PanacheRawQueryRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "PanacheRawQuery",
        severity = Severity.Security,
        description = "Panache query with interpolated string — use positional parameters (?1, ?2) instead",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.PANACHE_QUERY_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && firstArg.hasInterpolation()) {
            reportAt(
                expression,
                "Panache.$callee() with interpolated query — use ?1 positional parameters to prevent injection",
            )
        }
    }
}
