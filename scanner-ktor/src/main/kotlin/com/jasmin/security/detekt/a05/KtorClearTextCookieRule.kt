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
 * A Ktor Cookie created without secure=true will be sent over plain HTTP,
 * allowing network attackers to intercept session tokens.
 */
class KtorClearTextCookieRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorClearTextCookie",
        severity = Severity.Security,
        description = "Ktor Cookie without secure=true — transmitted over HTTP in cleartext",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_COOKIE_CLASS) return
        if (expression.valueArguments.isEmpty()) return
        val hasSecureTrue = expression.valueArguments.any { "secure" in it.text && "true" in it.text }
        if (hasSecureTrue) return
        reportAt(
            expression,
            "Ktor Cookie without secure=true — cookie will be sent over plain HTTP, add secure = true",
        )
    }
}
