package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (CSRF Token Exposure)
 * FindSecBugs: SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING
 *
 * Flags model.addAttribute() calls where the attribute name is a known CSRF token
 * keyword. Exposing the CSRF token in a model attribute may render it in HTML
 * responses or API payloads, leaking it to JavaScript (XSS) or logging systems.
 *
 * Compliant:
 *   model.addAttribute("user", user)          // non-sensitive key — safe
 *
 * Non-compliant:
 *   model.addAttribute("_csrf", csrfToken)    // exposes CSRF token in model
 *   model.addAttribute("csrfToken", token)    // exposes CSRF token in model
 */
class CsrfTokenLeakRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "CsrfTokenLeak",
        severity = Severity.Security,
        description = "CSRF token added to model attribute — may leak via HTML, JSON, or logs",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "addAttribute") return
        val nameArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val nameExpr = nameArg as? KtStringTemplateExpression ?: return
        if (nameExpr.hasInterpolation()) return
        val name = nameExpr.text.removeSurrounding("\"")
        if (DetectionPatterns.CSRF_TOKEN_KEYWORDS.any { name.contains(it, ignoreCase = true) }) {
            reportAt(
                expression,
                "addAttribute() exposes a CSRF token — use Spring's built-in CSRF support instead",
            )
        }
    }
}
