package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A01 — Broken Access Control (CWE-285)
 *
 * The reactive (WebFlux) equivalent of leaving everything public. On `ServerHttpSecurity`,
 * `authorizeExchange { anyExchange().permitAll() }` makes every endpoint accessible without
 * authentication, and `pathMatchers("/admin/..").permitAll()` opens a privileged path. The
 * MVC forms are covered elsewhere; this rule handles the reactive DSL.
 *
 * Non-compliant:
 *   http.authorizeExchange { it.anyExchange().permitAll() }
 *   http.authorizeExchange { it.pathMatchers("/admin/..").permitAll() }
 */
class ReactivePermitAllExchangeRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ReactivePermitAllExchange",
        severity = Severity.Security,
        description = "Reactive authorizeExchange permits all/admin paths — endpoints are unauthenticated",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "permitAll") return
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        when {
            receiver.endsWith("anyExchange()") ->
                reportAt(expression, "anyExchange().permitAll() makes all reactive endpoints public — use authenticated()")
            receiver.contains("pathMatchers") && DetectionPatterns.ADMIN_PATHS.any { receiver.contains(it) } ->
                reportAt(expression, "pathMatchers(...).permitAll() exposes a privileged path — require a role with hasRole(...)")
        }
    }
}
