package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A05 — Security Misconfiguration (CSRF / CWE-352)
 *
 * csrf { ignoringRequestMatchers("/api/...") } turns CSRF protection off for the
 * matched paths. State-changing endpoints behind those matchers become forgeable.
 * Exclude only stateless, token-authenticated APIs — and review every matcher.
 *
 * Non-compliant:
 *   http.csrf { it.ignoringRequestMatchers(apiPathPattern) }
 */
class SpringCsrfIgnoringMatchersRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringCsrfIgnoringMatchers",
        severity = Severity.Security,
        description = "CSRF protection excluded for matched paths — those endpoints become forgeable",
        debt = Debt.TWENTY_MINS,
    )

    private val ignoringMethods = setOf("ignoringRequestMatchers", "ignoringAntMatchers")

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in ignoringMethods) return
        reportAt(
            expression,
            "$callee() disables CSRF for the matched paths — exclude only stateless token-authenticated APIs",
        )
    }
}
