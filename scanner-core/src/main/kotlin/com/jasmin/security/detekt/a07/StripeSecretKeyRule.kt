package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 *
 * Stripe live secret keys (sk_live_) and restricted keys (rk_live_) can move real
 * money and read customer data. A hardcoded live key is a critical exposure and
 * must be rolled in the Stripe dashboard immediately.
 *
 * Non-compliant:
 *   val key = "sk_live_<24+ alphanumeric characters>"
 */
class StripeSecretKeyRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "StripeSecretKey",
        severity = Severity.Security,
        description = "Hardcoded Stripe live secret key — roll it and load from a secret manager",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (DetectionPatterns.STRIPE_SECRET_KEY_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "Hardcoded Stripe live secret key detected — roll it and load from a secret manager",
            )
        }
    }
}
