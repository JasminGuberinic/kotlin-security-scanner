package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: WEAK_TRUST_MANAGER
 *
 * Flags X509TrustManager implementations with an empty checkServerTrusted
 * or checkClientTrusted body. An empty body accepts all certificates including
 * expired, self-signed, or attacker-controlled ones — a common "quick fix"
 * that disables TLS certificate validation entirely.
 *
 * Compliant:
 *   override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
 *       // validate chain against a pinned cert or a proper trust store
 *   }
 *
 * Non-compliant:
 *   override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { }
 */
class TrustAllCertsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "TrustAllCerts",
        severity = Severity.Security,
        description = "Empty X509TrustManager check method accepts all certificates including invalid ones",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if (function.name !in DetectionPatterns.TRUST_CHECK_METHODS) return
        if (hasEmptyBody(function)) {
            reportAt(function, "${function.name}() is empty — all certificates are accepted, disabling TLS validation")
        }
    }

    private fun hasEmptyBody(function: KtNamedFunction): Boolean {
        val block = function.bodyBlockExpression ?: return false
        return block.statements.isEmpty()
    }
}
