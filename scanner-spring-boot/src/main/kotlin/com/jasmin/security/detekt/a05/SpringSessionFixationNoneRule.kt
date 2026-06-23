package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A05 — Security Misconfiguration (Session Fixation / CWE-384)
 *
 * sessionFixation { none() } keeps the same session ID across authentication, so a
 * pre-set session cookie remains valid after login — letting an attacker who planted
 * it ride the authenticated session. Spring migrates the session by default; keep
 * newSession()/migrateSession().
 *
 * Non-compliant:
 *   http.sessionManagement { sessionFixation { none() } }
 */
class SpringSessionFixationNoneRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringSessionFixationNone",
        severity = Severity.Security,
        description = "Session fixation protection set to none() — the session ID survives login",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val vulnerable = when (callee) {
            "sessionFixation" -> expression.lambdaArguments.any { it.text.contains("none") } ||
                expression.valueArguments.any { it.text.contains("none") }
            "none" -> (expression.parent as? KtDotQualifiedExpression)
                ?.receiverExpression?.text?.contains("sessionFixation") == true
            else -> false
        }
        if (vulnerable) {
            reportAt(expression, "sessionFixation none() keeps the session ID — use migrateSession() or newSession()")
        }
    }
}
