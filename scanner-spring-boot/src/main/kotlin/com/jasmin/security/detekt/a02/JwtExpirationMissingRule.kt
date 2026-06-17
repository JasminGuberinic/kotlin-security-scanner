package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: HARD_CODE_KEY
 *
 * A JJWT builder chain that calls .compact() without setExpiration() /
 * .expiration() produces tokens with no expiry — they remain valid indefinitely,
 * expanding the window after a credential compromise.
 *
 * Compliant:
 *   Jwts.builder().subject("user").setExpiration(Date()).compact()
 *
 * Non-compliant:
 *   Jwts.builder().subject("user").compact()
 */
class JwtExpirationMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "JwtExpirationMissing",
        severity = Severity.Security,
        description = "JWT compact() without expiration — tokens never expire",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.JWT_COMPACT_METHOD) return
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        val chainText = parent.text
        if ("builder" !in chainText) return
        if (hasExpirationInChain(chainText)) return
        reportAt(
            expression,
            "JWT .compact() without expiration — tokens never expire, increasing breach window",
        )
    }

    private fun hasExpirationInChain(text: String): Boolean =
        "setExpiration" in text || "expiration(" in text || "withExpiresAt" in text
}
