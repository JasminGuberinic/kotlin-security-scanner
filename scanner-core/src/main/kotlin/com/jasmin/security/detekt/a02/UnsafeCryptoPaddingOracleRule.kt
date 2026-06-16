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
 * FindSecBugs: PADDING_ORACLE
 *
 * AES/CBC/PKCS5Padding without a MAC (e.g. HMAC-SHA256) is vulnerable
 * to padding oracle attacks that decrypt ciphertext without the key.
 * Use AES/GCM/NoPadding which provides authenticated encryption (AEAD).
 *
 * Compliant:
 *   Cipher.getInstance("AES/GCM/NoPadding")
 *
 * Non-compliant:
 *   Cipher.getInstance("AES/CBC/PKCS5Padding")
 */
class UnsafeCryptoPaddingOracleRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "UnsafeCryptoPaddingOracle",
        severity = Severity.Security,
        description = "AES/CBC/PKCS5Padding is vulnerable to padding oracle attacks — use AES/GCM/NoPadding",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "getInstance") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val literal = firstArg as? KtStringTemplateExpression ?: return
        if (literal.hasInterpolation()) return
        if (literal.text.removeSurrounding("\"") != DetectionPatterns.UNSAFE_CBC_PADDING) return
        reportAt(
            expression,
            "AES/CBC/PKCS5Padding — vulnerable to padding oracle attacks. Use AES/GCM/NoPadding instead",
        )
    }
}
