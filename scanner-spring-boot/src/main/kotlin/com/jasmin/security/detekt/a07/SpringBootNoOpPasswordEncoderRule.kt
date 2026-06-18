package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// OWASP A07 — Identification and Authentication Failures
// NoOpPasswordEncoder stores passwords as plaintext — any database read exposes all credentials.
// Compliant:   BCryptPasswordEncoder()
// Non-compliant: NoOpPasswordEncoder.getInstance()
class SpringBootNoOpPasswordEncoderRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringBootNoOpPasswordEncoder",
        severity = Severity.Security,
        description = "NoOpPasswordEncoder stores passwords as cleartext — use BCryptPasswordEncoder",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "getInstance") return
        val dotExpr = expression.parent as? KtDotQualifiedExpression ?: return
        if (dotExpr.receiverExpression.text != "NoOpPasswordEncoder") return
        reportAt(
            dotExpr,
            "NoOpPasswordEncoder.getInstance() stores passwords as plaintext — use BCryptPasswordEncoder()",
        )
    }
}
