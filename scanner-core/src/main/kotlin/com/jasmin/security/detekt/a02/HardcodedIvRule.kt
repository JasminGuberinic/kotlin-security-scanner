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
 * FindSecBugs: STATIC_IV
 *
 * Flags IvParameterSpec constructed from a literal byteArrayOf(…).
 * A hardcoded IV makes every encryption of the same plaintext produce
 * the same ciphertext, defeating the purpose of CBC/CTR mode and enabling
 * pattern analysis attacks.
 *
 * Compliant:
 *   val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
 *   IvParameterSpec(iv)
 *
 * Non-compliant:
 *   IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
 */
class HardcodedIvRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedIv",
        severity = Severity.Security,
        description = "Hardcoded IV in IvParameterSpec — generate a random IV with SecureRandom for each encryption",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.IV_CONSTRUCTOR) return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtCallExpression ?: return
        if (arg.calleeExpression?.text == DetectionPatterns.BYTE_ARRAY_LITERAL &&
            arg.valueArguments.isNotEmpty()
        ) {
            reportAt(expression, "Static IV — use SecureRandom().nextBytes(iv) to generate a unique IV per encryption")
        }
    }
}
