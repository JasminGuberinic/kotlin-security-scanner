package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// A Ktor cookie session without cookie.domain allows the browser to send the session
// cookie to all subdomains, including attacker-controlled ones (subdomain takeover).
// Compliant:   cookie<MySession>("S") { cookie.domain = "app.example.com" }
// Non-compliant: cookie<MySession>("SESSION") { }  // no domain restriction
class KtorSessionCookieDomainMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorSessionCookieDomainMissing",
        severity = Severity.Security,
        description = "Ktor session cookie without domain restriction — vulnerable to subdomain takeover",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.KTOR_INSTALL) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg != DetectionPatterns.KTOR_SESSIONS_FEATURE) return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: return
        if ("cookie" !in lambdaText) return
        if ("cookie.domain" in lambdaText || ".domain" in lambdaText) return
        reportAt(
            expression,
            "Session cookie without .domain — set cookie.domain = \"app.example.com\" in Sessions config",
        )
    }
}
