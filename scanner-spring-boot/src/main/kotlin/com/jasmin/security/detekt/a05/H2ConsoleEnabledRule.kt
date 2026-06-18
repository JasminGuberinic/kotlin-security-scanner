package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A05 — Security Misconfiguration
 *
 * Enabling the H2 web console exposes a full SQL interface at /h2-console.
 * In production this gives any network-reachable caller unrestricted access
 * to the in-memory database, including schema inspection and data extraction.
 *
 * Compliant:
 *   %dev.spring.h2.console.enabled=true   (dev-only profile prefix)
 *   (omitted — default is false)
 *
 * Non-compliant:
 *   spring.h2.console.enabled=true
 *   %prod.spring.h2.console.enabled=true
 */
class H2ConsoleEnabledRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "H2ConsoleEnabled",
        severity = Severity.Security,
        description = "H2 web console enabled — exposes full SQL access in production",
        debt = Debt.TEN_MINS,
    )

    private val safeProfiles = setOf("dev", "test", "local", "it")

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if (!key.endsWith("spring.h2.console.enabled")) return@forEach
            if (value != "true") return@forEach
            val profile = if (key.startsWith("%")) key.substringBefore(".").drop(1) else ""
            if (profile in safeProfiles) return@forEach
            issues += key to "H2 console enabled outside a dev/test profile — set %prod.spring.h2.console.enabled=false"
        }
        return issues
    }
}
