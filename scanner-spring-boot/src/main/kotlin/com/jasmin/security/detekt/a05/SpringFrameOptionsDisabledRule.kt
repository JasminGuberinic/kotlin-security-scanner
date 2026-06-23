package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A05 — Security Misconfiguration (Clickjacking / CWE-1021)
 *
 * Disabling X-Frame-Options lets any site embed the app in an <iframe>, enabling
 * clickjacking. Spring sends DENY by default; an explicit frameOptions { disable() }
 * (or .frameOptions().disable()) removes that protection.
 *
 * Compliant:
 *   http.headers { frameOptions { sameOrigin() } }
 *
 * Non-compliant:
 *   http.headers { frameOptions { disable() } }
 */
class SpringFrameOptionsDisabledRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringFrameOptionsDisabled",
        severity = Severity.Security,
        description = "X-Frame-Options disabled — the app can be framed for clickjacking",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val disabled = when (callee) {
            "frameOptions" -> expression.lambdaArguments.any { it.text.contains("disable") } ||
                expression.valueArguments.any { it.text.contains("disable") }
            "disable" -> (expression.parent as? KtDotQualifiedExpression)
                ?.receiverExpression?.text?.contains("frameOptions") == true
            else -> false
        }
        if (disabled) {
            reportAt(expression, "frameOptions disabled — use sameOrigin() to keep clickjacking protection")
        }
    }
}
