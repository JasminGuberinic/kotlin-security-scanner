package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A02 — Cryptographic Failures (Improper Certificate Validation / CWE-295)
 *
 * Building a WebClient on a Reactor-Netty `HttpClient` whose SSL context trusts everything
 * (`InsecureTrustManagerFactory.INSTANCE`) disables TLS certificate validation, so a
 * man-in-the-middle can intercept the connection. Use a real trust store.
 *
 * Non-compliant:
 *   SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build()
 */
class WebClientInsecureSslRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "WebClientInsecureSsl",
        severity = Severity.Security,
        description = "WebClient/Reactor-Netty trusts all certificates (InsecureTrustManagerFactory) — disables TLS validation",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "trustManager") return
        val usesInsecure = expression.valueArguments.any { it.text.contains("InsecureTrustManagerFactory") }
        if (usesInsecure) {
            reportAt(
                expression,
                "trustManager(InsecureTrustManagerFactory) disables TLS validation — load a real trust store instead",
            )
        }
    }
}
