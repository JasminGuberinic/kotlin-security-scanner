package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: SSL_CONTEXT
 *
 * Flags calls that enable deprecated TLS 1.0 / TLS 1.1 or SSLv2/v3.
 * Matches setters like setSupportedProtocols("TLSv1.1") used in both
 * Dropwizard TlsConfiguration and raw javax/jakarta SSL config.
 *
 * Compliant:
 *   setSupportedProtocols("TLSv1.3")
 *
 * Non-compliant:
 *   setSupportedProtocols("TLSv1.0")
 *   setSslProtocol("SSLv3")
 */
class InsecureTlsProtocolRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureTlsProtocol",
        severity = Severity.Security,
        description = "Deprecated SSL/TLS protocol version is explicitly enabled",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)

        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.TLS_SETTER_NAMES) return

        expression.valueArguments
            .mapNotNull { it.getArgumentExpression() as? KtStringTemplateExpression }
            .filter { it.isLiteral() }
            .forEach { arg ->
                val value = arg.rawValue()
                if (isInsecureProtocol(value)) {
                    reportAt(expression, "$value is deprecated — use TLSv1.3 or TLSv1.2")
                }
            }
    }

    private fun isInsecureProtocol(protocol: String) =
        DetectionPatterns.INSECURE_TLS_PROTOCOLS.any { it.containsMatchIn(protocol) }
}
