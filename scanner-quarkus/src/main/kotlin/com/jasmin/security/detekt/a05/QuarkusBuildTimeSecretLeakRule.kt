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

    private fun isSecretKey(keyLower: String): Boolean =
        DetectionPatterns.CREDENTIAL_VARIABLE_KEYWORDS.any { it in keyLower }

    @Suppress("ReturnCount")
    private fun isHardcodedValue(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return false
        if (DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.any { it.containsMatchIn(trimmed) }) return false
        return true
    }
}
