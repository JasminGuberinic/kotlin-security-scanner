package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression

/**
 * OWASP A02 — Cryptographic Failures (Weak Key Size)
 * FindSecBugs: RSA_KEY_SIZE, BLOWFISH_KEY_SIZE
 *
 * Flags KeyPairGenerator.initialize() calls with a key size ≤ 1024 bits.
 * RSA-1024 is considered broken since 2010 — NIST requires ≥ 2048 bits through
 * 2030 and recommends 3072+ for longer lifetimes.
 *
 * Compliant:
 *   kpg.initialize(2048)   // RSA-2048 — acceptable
 *   kpg.initialize(4096)   // RSA-4096 — recommended
 *
 * Non-compliant:
 *   kpg.initialize(512)    // too short — broken
 *   kpg.initialize(1024)   // too short — deprecated
 */
class WeakRsaKeyRule(config: Config) : SecurityRule(config) {

    companion object {
        private const val MIN_SAFE_KEY_SIZE = 2048
    }

    override val issue = Issue(
        id = "WeakRsaKey",
        severity = Severity.Security,
        description = "KeyPairGenerator initialized with ≤ 1024-bit key — use ≥ 2048 bits for RSA",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount", "MagicNumber")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.KEY_GEN_INIT_METHOD) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val sizeExpr = firstArg as? KtConstantExpression ?: return
        val size = sizeExpr.text.toIntOrNull() ?: return
        if (size < MIN_SAFE_KEY_SIZE) {
            reportAt(
                expression,
                "Key size $size is too small — use ≥ 2048 bits for RSA, ≥ 256 bits for EC",
            )
        }
    }
}
