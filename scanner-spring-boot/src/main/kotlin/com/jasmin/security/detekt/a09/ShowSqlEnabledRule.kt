package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A09 — Security Logging and Monitoring Failures
 *
 * spring.jpa.show-sql=true prints every SQL statement to the log, which
 * exposes the database schema and query patterns. Combined with logging.level
 * DEBUG for Hibernate, it can also leak parameter values including passwords
 * and PII. Both should be disabled outside of a development profile.
 *
 * Compliant:
 *   %dev.spring.jpa.show-sql=true
 *   (omit — default is false)
 *
 * Non-compliant:
 *   spring.jpa.show-sql=true
 *   logging.level.org.hibernate.SQL=DEBUG
 */
class ShowSqlEnabledRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "ShowSqlEnabled",
        severity = Severity.Security,
        description = "SQL logging enabled — leaks schema and query patterns to application logs",
        debt = Debt.FIVE_MINS,
    )

    private val safeProfiles = setOf("dev", "test", "local", "it")

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            val profile = if (key.startsWith("%")) key.substringBefore(".").drop(1) else ""
            if (profile in safeProfiles) return@forEach
            when {
                key.endsWith("spring.jpa.show-sql") && value == "true" ->
                    issues += key to "SQL logging enabled — use %dev.spring.jpa.show-sql=true instead"

                key.endsWith("logging.level.org.hibernate.SQL") && value in setOf("DEBUG", "TRACE") ->
                    issues += key to "Hibernate SQL logging enabled — restrict to dev profile to avoid schema leakage"
            }
        }
        return issues
    }
}
