package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A07 — Identification and Authentication Failures
 *
 * Disabling TLS verification for Quarkus OIDC allows man-in-the-middle attacks
 * against the token endpoint — an attacker can intercept or forge tokens.
 * Hardcoding the OIDC client secret in properties leaks it with the artifact.
 *
 * Compliant:
 *   quarkus.oidc.tls.verification=certificate
 *   quarkus.oidc.credentials.secret=${OIDC_SECRET}
 *
 * Non-compliant:
 *   quarkus.oidc.tls.verification=none
 *   quarkus.oidc.credentials.secret=my-hardcoded-secret
 */
class QuarkusOidcInsecureConfigRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusOidcInsecureConfig",
        severity = Severity.Security,
        description = "Quarkus OIDC misconfigured — TLS disabled or secret hardcoded",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        val tlsKey = "quarkus.oidc.tls.verification"
        if (props.getProperty(tlsKey) == "none") {
            issues += tlsKey to "TLS verification disabled — MITM attacks against the OIDC token endpoint are possible"
        }
        val secretKey = "quarkus.oidc.credentials.secret"
        val secretValue = props.getProperty(secretKey)
        if (secretValue != null && isHardcoded(secretValue)) {
            issues += secretKey to "hardcoded OIDC client secret — use \${ENV_VAR} reference"
        }
        return issues
    }

    private fun isHardcoded(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return false
        return DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(trimmed) }
    }
}
