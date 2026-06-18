package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A07 — Identification and Authentication Failures
// Hardcoded database.password in Dropwizard configuration leaks the DB credential
// with every build artifact and container image.
// Compliant:   database.password=${DB_PASSWORD}
// Non-compliant: database.password=myS3cretP@ss
class DropwizardDatabasePasswordRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardDatabasePassword",
        severity = Severity.Security,
        description = "Dropwizard database.password hardcoded — use environment variable reference",
        debt = Debt.TEN_MINS,
    )

    private val passwordKeys = listOf("database.password", "database.user")

    @Suppress("ReturnCount")
    override fun scanProperties(props: Properties): List<Pair<String, String>> =
        passwordKeys.mapNotNull { key ->
            val value = props.getProperty(key) ?: return@mapNotNull null
            if (DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.any { it.containsMatchIn(value) }) {
                return@mapNotNull null
            }
            key to "Hardcoded database credential — use \${DB_PASSWORD} set in the deployment environment"
        }
}
