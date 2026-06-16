package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A01 — Broken Access Control
 * FindSecBugs: SPRING_CSRF_PROTECTION_DISABLED (similar pattern)
 *
 * Flags Spring Security configurations that call anyRequest().permitAll(), which
 * makes every HTTP endpoint publicly accessible without authentication. This is
 * often accidentally left in place after local development or testing.
 *
 * Compliant:
 *   auth.anyRequest().authenticated()           // all requests require auth
 *   auth.requestMatchers("/public").permitAll() // only specific paths are public
 *
 * Non-compliant:
 *   auth.anyRequest().permitAll()               // ALL requests are unauthenticated
 */
class DisabledHttpSecurityRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DisabledHttpSecurity",
        severity = Severity.Security,
        description = "anyRequest().permitAll() grants unauthenticated access to all endpoints",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "permitAll") return
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        if (!parent.receiverExpression.text.endsWith("anyRequest()")) return
        reportAt(
            expression,
            "anyRequest().permitAll() makes all endpoints public — use authenticated() or scope with requestMatchers()",
        )
    }
}
