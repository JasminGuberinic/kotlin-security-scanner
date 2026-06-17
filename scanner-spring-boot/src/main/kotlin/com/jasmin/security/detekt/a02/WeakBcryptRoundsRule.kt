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
 * FindSecBugs: WEAK_PASSWORD_ENCODER
 *
 * BCryptPasswordEncoder with fewer than 10 rounds completes too quickly for
 * offline brute-force attacks. Spring's own documentation recommends ≥ 10.
 *
 * Compliant:
 *   BCryptPasswordEncoder()          // defaults to strength 10
 *   BCryptPasswordEncoder(12)
 *
 * Non-compliant:
 *   BCryptPasswordEncoder(4)
 */
class WeakBcryptRoundsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "WeakBcryptRounds",
        severity = Severity.Security,
        description = "BCryptPasswordEncoder strength < 10 — brute-forceable offline",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount", "MagicNumber")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.BCRYPT_ENCODER_CLASS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val rounds = firstArg.text.toIntOrNull() ?: return
        if (rounds >= DetectionPatterns.BCRYPT_MIN_ROUNDS) return
        reportAt(
            expression,
            "BCryptPasswordEncoder strength $rounds is too weak — use at least ${DetectionPatterns.BCRYPT_MIN_ROUNDS}",
        )
    }
}
