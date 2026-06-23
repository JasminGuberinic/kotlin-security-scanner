package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// A cookie without HttpOnly can be read by JavaScript — XSS escalates to session hijack.
// Compliant:   ResponseCookie.from(name, value).httpOnly(true).build()
// Non-compliant: cookie.isHttpOnly = false
class SpringBootCookieNotHttpOnlyRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringBootCookieNotHttpOnly",
        severity = Severity.Security,
        description = "Cookie with HttpOnly disabled — JavaScript can read the cookie (XSS → session hijack)",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        val left = expression.left?.text ?: return
        val right = expression.right?.text ?: return
        if (!left.endsWith("isHttpOnly") && !left.endsWith("httpOnly")) return
        if (right != "false") return
        // Require the assignment target to reference a cookie — avoids flagging unrelated
        // properties like `featureToggle.httpOnly = false`.
        val receiver = left.substringBeforeLast(".")
        if (!receiver.contains("ookie")) return
        reportAt(expression, "Cookie HttpOnly disabled — set isHttpOnly = true to prevent JS access")
    }

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "httpOnly") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (arg.text != "false") return
        reportAt(expression, "Cookie HttpOnly disabled — set httpOnly(true) to prevent JS access")
    }
}
