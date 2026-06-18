package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A05 — Security Misconfiguration
// SmallRye Health exposes detailed liveness/readiness data including datasource
// names, queue depths, and cache stats. Enabling openapi on the health endpoint
// or routing it through the main port without auth leaks infrastructure topology.
// Compliant:   quarkus.smallrye-health.root-path=/q/health (routed to management port)
// Non-compliant: quarkus.smallrye-health.ui.enable=true in production
class QuarkusSmallRyeHealthInsecureRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusSmallRyeHealthInsecure",
        severity = Severity.Security,
        description = "SmallRye Health UI enabled in non-dev profile — leaks infrastructure topology",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            val profile = if (key.startsWith("%")) key.substringBefore(".").drop(1) else ""
            if (profile in setOf("dev", "test", "local")) return@forEach
            if (key.contains("smallrye-health") && key.endsWith("enable") && value == "true") {
                issues += key to "SmallRye Health UI enabled outside dev — restrict to management port or disable"
            }
        }
        return issues
    }
}
