package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtExpression

/**
 * OWASP A02 — Cryptographic Failures (CWE-335)
 *
 * Seeding SecureRandom with a constant or hardcoded byte array makes its output
 * deterministic — defeating the purpose of a cryptographically secure RNG.
 * An attacker who knows the seed can reproduce every "random" value.
 *
 * Compliant:
 *   val rng = SecureRandom()                        // OS-seeded automatically
 *
 * Non-compliant:
 *   SecureRandom(byteArrayOf(1, 2, 3, 4))           // hardcoded seed constructor
 *   SecureRandom().also { it.setSeed(12345L) }      // explicit constant seed
 */
class InsecureRandomSeedRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureRandomSeed",
        severity = Severity.Security,
        description = "SecureRandom seeded with a constant — predictable output defeats the purpose of a secure RNG",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        when (callee) {
            "setSeed" -> {
                val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
                if (!isHardcodedSeed(arg)) return
                reportAt(
                    expression,
                    "setSeed() with a constant makes the RNG output predictable — use SecureRandom() without a fixed seed",
                )
            }
            "SecureRandom" -> {
                val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
                if (!isHardcodedSeed(arg)) return
                reportAt(
                    expression,
                    "SecureRandom(seed) with hardcoded seed — use SecureRandom() (no-arg) for OS-seeded unpredictable output",
                )
            }
        }
    }

    private fun isHardcodedSeed(expr: KtExpression): Boolean {
        if (expr is KtConstantExpression) return true
        if (expr is KtCallExpression) {
            val innerCallee = expr.calleeExpression?.text ?: return false
            if (innerCallee != "byteArrayOf") return false
            return expr.valueArguments.all { it.getArgumentExpression() is KtConstantExpression }
        }
        return false
    }
}
