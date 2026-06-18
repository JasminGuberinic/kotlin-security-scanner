package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A03 — Injection
// EntityManager.createNativeQuery(nonLiteral) concatenates user input into SQL,
// bypassing JPA parameter binding and enabling full SQL injection.
// Compliant:   em.createNativeQuery("SELECT * FROM users WHERE id = :id").setParameter("id", id)
// Non-compliant: em.createNativeQuery("SELECT * FROM users WHERE id = $id")
class QuarkusNativeQueryInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusNativeQueryInjection",
        severity = Severity.Security,
        description = "createNativeQuery() with dynamic string — use named parameters to prevent SQL injection",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "createNativeQuery" && callee != "createQuery") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        reportAt(
            expression,
            "$callee() with non-literal query — use setParameter() instead of string concatenation",
        )
    }
}
