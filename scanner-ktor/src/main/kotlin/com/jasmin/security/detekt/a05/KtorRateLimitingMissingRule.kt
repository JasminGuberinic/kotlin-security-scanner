package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// A state-changing Ktor route (POST/PUT/DELETE/PATCH) without reading the CSRF
// header or Origin is vulnerable to cross-site request forgery.
// Compliant:   rateLimited { post("/login") { ... } }
// Non-compliant: post("/login") { ... }  // in routing block without rate limiting
class KtorRateLimitingMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorRateLimitingMissing",
        severity = Severity.Security,
        description = "Ktor login/auth route without rate limiting — brute-force attack possible",
        debt = Debt.TWENTY_MINS,
    )

    private val authPaths = setOf("/login", "/auth", "/token", "/signin", "/authenticate")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in setOf("post", "get", "put")) return
        val pathArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        val path = pathArg.trim('"')
        if (authPaths.none { it in path }) return
        if (isInsideRateLimiting(expression)) return
        reportAt(
            expression,
            "Auth route $path without rate limiting — install RateLimit plugin or wrap in rateLimited{}",
        )
    }

    private fun isInsideRateLimiting(expression: KtCallExpression): Boolean {
        var current = expression.parent
        while (current != null) {
            if (current is KtCallExpression) {
                val callText = current.calleeExpression?.text ?: ""
                if ("rateLimited" in callText || "RateLimit" in callText) return true
            }
            current = current.parent
        }
        return false
    }
}
