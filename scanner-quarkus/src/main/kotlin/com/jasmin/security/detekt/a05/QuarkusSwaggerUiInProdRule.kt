package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A05 — Security Misconfiguration
// Swagger UI in production exposes your full API surface, authentication flows,
// and example payloads — making reconnaissance trivial for attackers.
// Compliant:   %dev.quarkus.swagger-ui.always-include=true
// Non-compliant: quarkus.swagger-ui.always-include=true (applies to all profiles)
class QuarkusSwaggerUiInProdRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusSwaggerUiInProd",
        severity = Severity.Security,
        description = "Swagger UI always-include=true — API explorer exposed in production",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            val profile = if (key.startsWith("%")) key.substringBefore(".").drop(1) else ""
            if (profile in setOf("dev", "test", "local")) return@forEach
            if ("swagger-ui" in key && key.endsWith("always-include") && value == "true") {
                issues += key to "Swagger UI enabled in non-dev profile — restrict with %dev. prefix"
            }
        }
        return issues
    }
}
