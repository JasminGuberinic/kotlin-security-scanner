package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A05 — Security Misconfiguration (Sensitive Cookie Without 'Secure' / CWE-614)
 *
 * Calling `.setSecure(false)` on a Vert.x cookie sends it over plain HTTP, where it can be
 * captured on the network. Session / auth cookies must be marked secure (and httpOnly).
 *
 * Compliant:
 *   Cookie.cookie("session", id).setSecure(true).setHttpOnly(true)
 *
 * Non-compliant:
 *   Cookie.cookie("session", id).setSecure(false)
 */
class VertxInsecureCookieRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxInsecureCookie",
        severity = Severity.Security,
        description = "Vert.x cookie setSecure(false) — sent over plain HTTP",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "setSecure") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
        if (arg.text != "false") return
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        if (!receiver.contains("ookie")) return
        reportAt(expression, "Cookie.setSecure(false) sends the cookie over plain HTTP — call .setSecure(true)")
    }
}
