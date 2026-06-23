package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A05 — Security Misconfiguration / A07 — Identification and Auth Failures
 *
 * Quarkus build-time properties (application.properties) are bundled into the
 * native image or JAR and can be extracted. Hardcoding secrets here leaks them
 * to anyone with access to the artifact.
 *
 * Compliant:
 *   quarkus.datasource.password=${DB_PASSWORD}
 *   %prod.quarkus.datasource.password=${DB_PASSWORD}
 *
 * Non-compliant:
 *   quarkus.datasource.password=mysecretpassword
 */
class QuarkusBuildTimeSecretLeakRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusBuildTimeSecretLeak",
        severity = Severity.Security,
        description = "Hardcoded secret in application.properties — use environment variable reference",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        for ((rawKey, rawValue) in props) {
            val key = rawKey.toString().lowercase()
            val value = rawValue.toString()
            if (isSecretKey(key) && isHardcodedValue(value)) {
                issues += rawKey.toString() to "hardcoded value — use \${ENV_VAR} reference instead"
            }
        }
        return issues
    }

    // Dot/dash-delimited key SEGMENTS are matched against secret keywords, so a key like
    // "quarkus.oidc.auth-server-url" is NOT flagged just because it contains "auth". The
    // over-broad bare "auth"/"token" tokens are deliberately excluded from this property
    // scan; "api-key" splits to [api, key] so its joined form "apikey" is also accepted.
    private val secretKeySegments = setOf(
        "password", "passwd", "pwd", "secret", "apikey", "api_key", "apisecret",
        "credential", "credentials", "private_key", "privatekey",
        "access_key", "accesskey", "client_secret", "clientsecret",
    )

    private fun isSecretKey(keyLower: String): Boolean {
        val segments = keyLower.split('.', '-').filter { it.isNotEmpty() }
        if (segments.any { it in secretKeySegments }) return true
        // Also accept adjacent segment pairs joined, so "api-key" → "apikey" matches.
        for (i in 0 until segments.size - 1) {
            if (segments[i] + segments[i + 1] in secretKeySegments) return true
        }
        return false
    }

    @Suppress("ReturnCount")
    private fun isHardcodedValue(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return false
        if (DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.any { it.containsMatchIn(trimmed) }) return false
        return true
    }
}
