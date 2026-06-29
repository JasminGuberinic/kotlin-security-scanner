package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression

/**
 * OWASP A02 — Cryptographic Failures (Improper Certificate Validation / CWE-295)
 *
 * `HttpClientOptions().setTrustAll(true)` and `WebClientOptions().setVerifyHost(false)`
 * disable TLS certificate / hostname verification on a Vert.x client, so any server
 * (including a man-in-the-middle) is accepted. Use a proper trust store and keep host
 * verification on.
 *
 * Non-compliant:
 *   HttpClientOptions().setSsl(true).setTrustAll(true)
 *   WebClientOptions().setVerifyHost(false)
 */
class VertxTrustAllCertsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxTrustAllCerts",
        severity = Severity.Security,
        description = "Vert.x client disables TLS verification (setTrustAll(true)/setVerifyHost(false))",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
        val insecure = (callee == "setTrustAll" && arg.text == "true") ||
            (callee == "setVerifyHost" && arg.text == "false")
        if (insecure) {
            reportAt(
                expression,
                "$callee(${arg.text}) disables TLS verification on a Vert.x client — use a trust store and keep host verification on",
            )
        }
    }
}
