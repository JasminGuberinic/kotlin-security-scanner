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
 * A hardcoded quarkus.datasource.password leaks the database credential
 * with every build artifact and source-code checkout.
 */
class QuarkusHardcodedDatasourcePasswordRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusHardcodedDatasourcePassword",
        severity = Severity.Security,
        description = "quarkus.datasource.password hardcoded — use environment variable reference",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "quarkus.datasource.password"
        val value = props.getProperty(key) ?: return emptyList()
        return if (isHardcoded(value)) {
            listOf(key to "hardcoded datasource password — use \${DB_PASSWORD} environment variable")
        } else {
            emptyList()
        }
    }

    private fun isHardcoded(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return false
        return DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(trimmed) }
    }
}
