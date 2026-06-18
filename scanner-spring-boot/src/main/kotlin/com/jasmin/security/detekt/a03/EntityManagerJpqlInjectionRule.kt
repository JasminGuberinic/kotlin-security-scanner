package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
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
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        reportAt(
            expression,
            "$callee() with dynamic string — use named params: .setParameter(\"name\", value)",
        )
    }
}
