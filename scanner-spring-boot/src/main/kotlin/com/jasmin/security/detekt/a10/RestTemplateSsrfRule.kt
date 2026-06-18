package com.jasmin.security.detekt.a10

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A10 — Server-Side Request Forgery
 *
 * Passing a user-controlled URL directly to RestTemplate methods allows
 * attackers to redirect requests to internal services, cloud metadata
 * endpoints (169.254.169.254), or internal DNS names.
 *
 * Compliant:
 *   val url = "https://api.trusted.com/data"
 *   restTemplate.getForObject(url, String::class.java)
 *
 * Non-compliant:
 *   restTemplate.getForObject(userInput, String::class.java)
 *   restTemplate.getForObject("https://service/${userId}", String::class.java)
 */
class RestTemplateSsrfRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "RestTemplateSsrf",
        severity = Severity.Security,
        description = "RestTemplate call with dynamic URL — validate host against allowlist to prevent SSRF",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val method = callee.substringAfterLast(".")
        if (method !in DetectionPatterns.REST_TEMPLATE_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        reportAt(
            expression,
            "$method() uses a dynamic URL — validate URI host against an allowlist before the call",
        )
    }
}
