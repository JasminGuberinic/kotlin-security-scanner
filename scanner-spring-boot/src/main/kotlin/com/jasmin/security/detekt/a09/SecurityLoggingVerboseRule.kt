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
 * DEBUG/TRACE logging for Spring Security or Spring OAuth2 logs authentication
 * decisions, filter chain evaluations, and token details to the application log.
 * In production this can expose user credentials, JWT payloads, and session tokens
 * to anyone with log read access.
 *
 * Compliant:
 *   %dev.logging.level.org.springframework.security=DEBUG
 *
 * Non-compliant:
 *   logging.level.org.springframework.security=DEBUG
 */
class SecurityLoggingVerboseRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "SecurityLoggingVerbose",
        severity = Severity.Security,
        description = "Spring Security DEBUG logging in production leaks auth decisions and token details",
        debt = Debt.FIVE_MINS,
    )

    private val sensitiveLoggers = listOf(
        "logging.level.org.springframework.security",
        "logging.level.org.springframework.security.web",
        "logging.level.org.springframework.security.oauth2",
    )
    private val verboseLevels = setOf("DEBUG", "TRACE")
    private val safeProfiles = setOf("dev", "test", "local", "it")

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim().uppercase()
            val profile = if (key.startsWith("%")) key.substringBefore(".").drop(1) else ""
            if (profile in safeProfiles) return@forEach
            if (sensitiveLoggers.none { key.endsWith(it.removePrefix("logging.level.")) || key == it }) return@forEach
            if (value !in verboseLevels) return@forEach
            issues += key to "Security DEBUG logging outside dev — leaks auth decisions and token details to logs"
        }
        return issues
    }
}
