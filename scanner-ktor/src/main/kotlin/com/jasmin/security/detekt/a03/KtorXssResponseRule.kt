package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (XSS)
 * call.respondText with ContentType.Text.Html and a dynamically built string
 * can reflect unescaped user input as HTML, enabling cross-site scripting attacks.
 */
class KtorXssResponseRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorXssResponse",
        severity = Severity.Security,
        description = "call.respondText with HTML content type and dynamic content — potential XSS",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_RESPOND_TEXT) return
        val argsText = expression.valueArguments.joinToString(" ") { it.text }
        if ("Html" !in argsText) return
        val contentArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (contentArg is KtStringTemplateExpression && !contentArg.hasInterpolation()) return
        reportAt(
            expression,
            "call.respondText with HTML content type and dynamic content — escape user input to prevent XSS",
        )
    }
}
