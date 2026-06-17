package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A05 — Security Misconfiguration
 *
 * install(CORS) { anyHost() } allows cross-origin requests from any domain.
 * Combined with withCredentials, this exposes authenticated endpoints to
 * cross-site request forgery from any origin.
 *
 * Compliant:
 *   install(CORS) { allowHost("api.example.com", schemes = listOf("https")) }
 *
 * Non-compliant:
 *   install(CORS) { anyHost() }
 */
class KtorPermissiveCorsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorPermissiveCors",
        severity = Severity.Security,
        description = "Ktor CORS allows any host (anyHost()) — specify allowed origins explicitly",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_INSTALL) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg != DetectionPatterns.KTOR_CORS_FEATURE) return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: return
        if (DetectionPatterns.KTOR_ANY_HOST !in lambdaText) return
        reportAt(
            expression,
            "Ktor CORS uses anyHost() — restrict to specific allowed origins with allowHost()",
        )
    }
}
