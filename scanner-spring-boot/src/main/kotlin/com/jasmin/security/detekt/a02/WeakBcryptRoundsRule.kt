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
 * BCryptPasswordEncoder with fewer than [minStrength] rounds completes too quickly for
 * offline brute-force attacks. Spring's own documentation recommends ≥ 10.
 *
 * Configure in detekt.yml:
 *   WeakBcryptRounds:
 *     active: true
 *     minStrength: 12   # default: 10 (NIST SP 800-63B minimum)
 *
 * Compliant:
 *   BCryptPasswordEncoder()          // defaults to strength 10
 *   BCryptPasswordEncoder(12)
 *
 * Non-compliant:
 *   BCryptPasswordEncoder(4)
 */
class WeakBcryptRoundsRule(config: Config) : SecurityRule(config) {

    private val minStrength: Int = config.valueOrDefault("minStrength", DetectionPatterns.BCRYPT_MIN_ROUNDS)

    override val issue = Issue(
        id = "WeakBcryptRounds",
        severity = Severity.Security,
        description = "BCryptPasswordEncoder strength below minimum — brute-forceable offline",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.BCRYPT_ENCODER_CLASS) return
        // BCryptPasswordEncoder(strength), BCryptPasswordEncoder(version, strength),
        // and BCryptPasswordEncoder(strength = n) — locate the strength argument explicitly.
        val named = expression.valueArguments.firstOrNull {
            it.getArgumentName()?.asName?.asString() == "strength"
        }
        val rounds = if (named != null) {
            named.getArgumentExpression()?.text?.toIntOrNull() ?: return
        } else {
            expression.valueArguments
                .mapNotNull { it.getArgumentExpression()?.text?.toIntOrNull() }
                .firstOrNull() ?: return
        }
        if (rounds >= minStrength) return
        reportAt(
            expression,
            "BCryptPasswordEncoder strength $rounds is too weak — use at least $minStrength",
        )
    }
}
