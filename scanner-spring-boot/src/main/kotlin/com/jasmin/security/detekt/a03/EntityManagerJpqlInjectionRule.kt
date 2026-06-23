package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (JPQL / Native SQL via EntityManager)
 *
 * Concatenating or interpolating user input into a JPQL or native SQL string
 * passed to EntityManager.createQuery() / createNativeQuery() enables injection
 * that can leak, modify, or delete data.
 *
 * Compliant:
 *   em.createQuery("SELECT u FROM User u WHERE u.name = :name")
 *     .setParameter("name", name)
 *
 * Non-compliant:
 *   em.createQuery("SELECT u FROM User u WHERE u.name = '$name'")
 *   em.createNativeQuery("SELECT * FROM users WHERE id = " + id)
 */
class EntityManagerJpqlInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "EntityManagerJpqlInjection",
        severity = Severity.Security,
        description = "EntityManager query built with dynamic string — use named parameters to prevent injection",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.ENTITY_MANAGER_QUERY_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (isConstantString(firstArg)) return
        reportAt(
            expression,
            "$callee() with dynamic string — use named params: .setParameter(\"name\", value)",
        )
    }

    // A bare non-interpolated string literal OR a '+' concatenation of constant strings is safe.
    private fun isConstantString(expr: KtExpression): Boolean = when (expr) {
        is KtStringTemplateExpression -> !expr.hasInterpolation()
        is KtBinaryExpression -> {
            val left = expr.left
            val right = expr.right
            left != null && right != null &&
                isConstantString(left) && isConstantString(right)
        }
        else -> false
    }
}
