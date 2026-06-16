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
 * FindSecBugs: WEAK_MESSAGE_DIGEST_MD5, WEAK_MESSAGE_DIGEST_SHA1
 *
 * Flags MessageDigest.getInstance() called with MD5 or SHA-1.
 * Both algorithms are cryptographically broken and trivially reversible
 * with rainbow tables — never use for passwords, signatures, or integrity checks.
 *
 * Compliant:
 *   MessageDigest.getInstance("SHA-256")
 *   MessageDigest.getInstance("SHA-512")
 *
 * Non-compliant:
 *   MessageDigest.getInstance("MD5")
 *   MessageDigest.getInstance("SHA-1")
 */
class WeakHashAlgorithmRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "WeakHashAlgorithm",
        severity = Severity.Security,
        description = "MD5 and SHA-1 are cryptographically broken — use SHA-256 or stronger",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (!isGetInstanceCall(expression)) return
        val algorithm = firstLiteralArg(expression) ?: return
        if (isWeakAlgorithm(algorithm)) {
            reportAt(expression, "\"$algorithm\" is broken — replace with SHA-256 or SHA-512")
        }
    }

    private fun isGetInstanceCall(expression: KtCallExpression) =
        expression.calleeExpression?.text == "getInstance"

    @Suppress("ReturnCount")
    private fun firstLiteralArg(expression: KtCallExpression): String? {
        val arg = expression.valueArguments.firstOrNull()
            ?.getArgumentExpression() as? KtStringTemplateExpression ?: return null
        if (arg.hasInterpolation()) return null
        return arg.text.removeSurrounding("\"")
    }

    private fun isWeakAlgorithm(algorithm: String) =
        DetectionPatterns.WEAK_HASH_ALGORITHMS.any { it.matches(algorithm) }
}
