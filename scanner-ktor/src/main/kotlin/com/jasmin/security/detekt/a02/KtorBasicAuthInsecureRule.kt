package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A02 — Cryptographic Failures
 * Ktor's basic { } auth sends credentials as base64-encoded username:password over the wire.
 * Without enforced HTTPS this is equivalent to plaintext transmission.
 */
class KtorBasicAuthInsecureRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorBasicAuthInsecure",
        severity = Severity.Security,
        description = "Ktor Basic Authentication — credentials sent base64-encoded, enforce HTTPS",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_BASIC_AUTH) return
        if (expression.lambdaArguments.isEmpty()) return
        reportAt(
            expression,
            "Ktor Basic Auth sends credentials base64-encoded — pair with HTTPS or prefer a stronger auth mechanism",
        )
    }
}
