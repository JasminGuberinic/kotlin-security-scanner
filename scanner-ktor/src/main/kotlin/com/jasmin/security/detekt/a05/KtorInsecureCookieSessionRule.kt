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
 * Ktor Sessions stored in cookies without a SessionTransportTransformerEncrypt
 * or SessionTransportTransformerMessageAuthentication are sent in plaintext —
 * the client can read and forge session contents.
 *
 * Compliant:
 *   install(Sessions) { cookie<UserSession>("S") { transform(SessionTransportTransformerEncrypt(k, s)) } }
 *
 * Non-compliant:
 *   install(Sessions) { cookie<UserSession>("SESSION") }
 */
class KtorInsecureCookieSessionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorInsecureCookieSession",
        severity = Severity.Security,
        description = "Ktor Sessions cookie without encryption — session data can be read and forged",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_INSTALL) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg != DetectionPatterns.KTOR_SESSIONS_FEATURE) return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: return
        if ("cookie" !in lambdaText) return
        if ("transform" in lambdaText || "encrypt" in lambdaText.lowercase()) return
        reportAt(
            expression,
            "Ktor Sessions cookie without encryption transform — use SessionTransportTransformerEncrypt",
        )
    }
}
