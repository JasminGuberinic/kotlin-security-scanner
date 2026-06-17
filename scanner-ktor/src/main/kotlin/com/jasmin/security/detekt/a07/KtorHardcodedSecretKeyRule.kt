package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 * SessionTransportTransformerEncrypt/MessageAuthentication with a literal string key
 * leaks the encryption/signing key in source code — anyone with repo access can forge sessions.
 */
class KtorHardcodedSecretKeyRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorHardcodedSecretKey",
        severity = Severity.Security,
        description = "Ktor session transform with hardcoded key — load key from environment variable",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.KTOR_SESSION_TRANSFORM_CLASSES) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression) return
        if (firstArg.hasInterpolation()) return
        reportAt(
            expression,
            "$callee with hardcoded key — load encryption key from environment variable or secure vault",
        )
    }
}
