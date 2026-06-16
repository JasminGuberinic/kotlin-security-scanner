package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (Open Redirect)
 * FindSecBugs: SPRING_UNVALIDATED_REDIRECT
 *
 * Flags Spring MVC view redirects built with string concatenation or
 * interpolation. An attacker can supply a crafted URL to redirect users
 * to a phishing site while the origin appears trustworthy.
 *
 * Compliant:
 *   return "redirect:/dashboard"          // literal path — safe
 *
 * Non-compliant:
 *   return "redirect:${'$'}returnUrl"     // interpolated — attacker-controlled
 *   return "redirect:" + request.getParameter("next")
 */
class OpenRedirectRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "OpenRedirect",
        severity = Severity.Security,
        description = "Spring redirect target built from non-literal input — validate against an allowlist",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (!expression.hasInterpolation()) return
        val firstText = expression.entries.firstOrNull()?.text ?: return
        if (firstText.startsWith(DetectionPatterns.REDIRECT_PREFIX)) {
            reportAt(expression, "Redirect target contains interpolated input — validate against a safe path allowlist")
        }
    }

    @Suppress("ReturnCount")
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        if (expression.operationReference.text != "+") return
        val left = expression.left as? KtStringTemplateExpression ?: return
        if (!left.isLiteral()) return
        if (left.rawValue().startsWith(DetectionPatterns.REDIRECT_PREFIX)) {
            reportAt(expression, "Redirect target built by concatenation — validate against a safe path allowlist")
        }
    }
}
