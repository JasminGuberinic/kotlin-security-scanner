package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 *
 * SSLContext.getInstance("SSL"|"SSLv3"|"TLSv1"|"TLSv1.1") pins the connection to a
 * protocol with known breaks (POODLE, BEAST). Request "TLS" (negotiates the highest
 * mutually supported version) or "TLSv1.2"/"TLSv1.3" explicitly.
 *
 * Compliant:
 *   SSLContext.getInstance("TLSv1.3")
 *
 * Non-compliant:
 *   SSLContext.getInstance("SSLv3")
 *   SSLContext.getInstance("TLSv1.1")
 */
class InsecureSslContextRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureSslContext",
        severity = Severity.Security,
        description = "SSLContext pinned to a deprecated protocol — request TLSv1.2 or TLSv1.3",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "getInstance") return
        // Confirm the receiver is SSLContext to avoid matching MessageDigest/Cipher getInstance.
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        if (!receiver.endsWith(DetectionPatterns.SSL_CONTEXT_CLASS)) return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (arg !is KtStringTemplateExpression || arg.hasInterpolation()) return
        val protocol = arg.rawValue()
        if (DetectionPatterns.WEAK_SSL_PROTOCOLS.any { it.matches(protocol) }) {
            reportAt(
                expression,
                "SSLContext.getInstance(\"$protocol\") uses a deprecated protocol — request TLSv1.2 or TLSv1.3",
            )
        }
    }
}
