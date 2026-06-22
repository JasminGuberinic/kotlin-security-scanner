package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A05 — Security Misconfiguration
 *
 * allowedOrigins("*") / addAllowedOrigin("*") permits any domain to make cross-origin
 * requests. Combined with credentials, this bypasses the Same-Origin Policy entirely.
 *
 * Applies to: Micronaut CORS configuration, Spring CORS (addAllowedOrigin), Ktor, and
 * any framework using a CORS builder with allowedOrigins or addAllowedOrigin.
 *
 * Compliant:
 *   allowedOrigins("https://app.example.com", "https://admin.example.com")
 *
 * Non-compliant:
 *   allowedOrigins("*")       // Micronaut CorsOriginConfiguration
 *   addAllowedOrigin("*")     // Spring CorsConfiguration
 */
class CorsWildcardOriginsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "CorsWildcardOrigins",
        severity = Severity.Security,
        description = "CORS configured with wildcard origin '*' — restricts the Same-Origin Policy for all domains",
        debt = Debt.TWENTY_MINS,
    )

    private val corsOriginMethods = setOf(
        "allowedOrigins", "addAllowedOrigin", "allowedOriginsRegex",
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee !in corsOriginMethods) return
        val hasWildcard = expression.valueArguments.any { arg ->
            val expr = arg.getArgumentExpression()
            expr is KtStringTemplateExpression && !expr.hasInterpolation() && expr.rawValue() == "*"
        }
        if (!hasWildcard) return
        reportAt(
            expression,
            "CORS $callee(\"*\") allows any domain — specify trusted origins explicitly",
        )
    }
}
