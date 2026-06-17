package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A01 — Broken Access Control
 *
 * A Ktor routing {} block that contains no authenticate {} wrapper exposes
 * all routes to unauthenticated callers. Every handler inside routing should
 * be wrapped in at least one authenticate("provider-name") { } block.
 *
 * Compliant:
 *   routing { authenticate("auth-jwt") { get("/users") { ... } } }
 *
 * Non-compliant:
 *   routing { get("/users") { ... } }
 */
class KtorMissingAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorMissingAuth",
        severity = Severity.Security,
        description = "Ktor routing{} without authenticate{} — all routes are publicly accessible",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_ROUTING) return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: return
        if ("authenticate" in lambdaText) return
        reportAt(
            expression,
            "Ktor routing{} has no authenticate{} block — wrap sensitive routes with authenticate(\"provider\")",
        )
    }
}
