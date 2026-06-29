package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures (Hardcoded Credentials / CWE-798)
 *
 * A Vert.x symmetric JWT key set from a string literal — `PubSecKeyOptions().setBuffer("secret")`
 * — bakes the signing secret into source, so anyone with the code can forge valid tokens. Load
 * the secret from the environment or a key store.
 *
 * Non-compliant:
 *   PubSecKeyOptions().setAlgorithm("HS256").setBuffer("my-hardcoded-jwt-secret")
 */
class VertxHardcodedJwtSecretRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxHardcodedJwtSecret",
        severity = Severity.Security,
        description = "PubSecKeyOptions.setBuffer(literal) — hardcoded JWT signing secret",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text?.substringAfterLast(".") != "setBuffer") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        if (arg.hasInterpolation() || arg.rawValue().isEmpty()) return
        // Confirm we're on a JWT key options builder to avoid matching unrelated setBuffer calls.
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        if (!receiver.contains("PubSecKey")) return
        reportAt(
            expression,
            "PubSecKeyOptions.setBuffer with a hardcoded secret — load the JWT key from the environment or a key store",
        )
    }
}
