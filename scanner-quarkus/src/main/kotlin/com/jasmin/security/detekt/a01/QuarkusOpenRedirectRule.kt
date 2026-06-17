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
 * OWASP A01 — Broken Access Control
 * Response.temporaryRedirect(URI(userInput)) lets an attacker redirect users to a malicious site.
 */
class QuarkusOpenRedirectRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusOpenRedirect",
        severity = Severity.Security,
        description = "JAX-RS redirect with dynamic URI — validate target to prevent open redirect",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.JAXRS_REDIRECT_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtCallExpression) return
        val innerCallee = firstArg.calleeExpression?.text ?: return
        if (innerCallee != "URI") return
        val uriArg = firstArg.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (uriArg is KtStringTemplateExpression && !uriArg.hasInterpolation()) return
        reportAt(
            expression,
            "JAX-RS $callee() with dynamic URI — validate the redirect target to prevent open redirect",
        )
    }
}
