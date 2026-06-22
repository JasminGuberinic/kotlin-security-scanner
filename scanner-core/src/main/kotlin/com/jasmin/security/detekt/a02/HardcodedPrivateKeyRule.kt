package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 *
 * PEM private key material embedded in source code is readable by anyone with
 * access to the repository or build artifact. A leaked private key cannot be
 * "un-leaked" — all data it was used to protect must be considered compromised.
 *
 * Compliant:
 *   val key = KeyStore.getInstance("PKCS12").apply { load(...) }
 *
 * Non-compliant:
 *   val pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."
 */
class HardcodedPrivateKeyRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedPrivateKey",
        severity = Severity.Security,
        description = "Private key PEM material in source code — load from a secure KeyStore",
        debt = Debt.TWENTY_MINS,
    )

    private val pemHeaders = listOf(
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val value = expression.rawValue()
        if (pemHeaders.any { it in value }) {
            reportAt(
                expression,
                "Private key PEM header found in string literal — load from a KeyStore or inject via environment variable",
            )
        }
    }
}
