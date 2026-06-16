package com.jasmin.security.detekt.a10

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
 * OWASP A10 — Server-Side Request Forgery (SSRF)
 * FindSecBugs: URLCONNECTION_SSRF_FD
 *
 * WebClient.create(url) with a non-literal URL allows an attacker
 * to direct server-side HTTP requests to internal network targets.
 * Complements SsrfRule which covers RestTemplate / java.net.URL.
 *
 * Compliant:
 *   WebClient.create("https://api.internal/v1")
 *
 * Non-compliant:
 *   WebClient.create(request.getParameter("url"))
 */
class WebClientSSRFRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "WebClientSSRF",
        severity = Severity.Security,
        description = "WebClient.create() with dynamic URL — validate against an allowlist to prevent SSRF",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.WEB_CLIENT_CREATE) return
        val parentDot = expression.parent as? KtDotQualifiedExpression ?: return
        if (!parentDot.receiverExpression.text.endsWith(DetectionPatterns.WEB_CLIENT_CLASS)) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (isSafe) return
        reportAt(
            expression,
            "WebClient.create() with non-literal URL — validate against an allowlist to prevent SSRF",
        )
    }
}
