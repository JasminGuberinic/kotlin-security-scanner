package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression

// OWASP A05 — Security Misconfiguration
// NewCookie without Secure and HttpOnly flags allows the session cookie to be
// transmitted over HTTP and accessed by JavaScript (XSS → session hijack).
// Compliant:   NewCookie.Builder("SESSION").secure(true).httpOnly(true).build()
// Non-compliant: NewCookie("SESSION", token)  // all defaults = insecure
class QuarkusInsecureCookieRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusInsecureCookie",
        severity = Severity.Security,
        description = "JAX-RS NewCookie without secure/httpOnly — vulnerable to interception and XSS",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val dotExpr = expression.parent as? KtDotQualifiedExpression

        val isNewCookieCtor = callee == "NewCookie"
        // Accept both the simple name "NewCookie.Builder(...)" and the fully-qualified
        // form "jakarta.ws.rs.core.NewCookie.Builder(...)" by comparing the last segment.
        val isNewCookieBuilder = callee == "Builder" &&
            dotExpr?.receiverExpression?.text?.substringAfterLast(".") == "NewCookie"

        if (!isNewCookieCtor && !isNewCookieBuilder) return

        // Walk up to get the entire method-chain text
        val chainText = fullChainText(dotExpr ?: expression)
        if ("secure(true)" in chainText && "httpOnly(true)" in chainText) return
        reportAt(
            expression,
            "NewCookie without secure(true) and httpOnly(true) — " +
                "use NewCookie.Builder(name).secure(true).httpOnly(true).build()",
        )
    }

    private fun fullChainText(start: KtExpression): String {
        var top: KtExpression = start
        while (true) {
            top = top.parent as? KtDotQualifiedExpression ?: break
        }
        return top.text
    }
}
