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
 * Exposing all Spring Boot Actuator endpoints via wildcard leaks heap dumps,
 * thread state, environment variables, and metric data to any authenticated
 * (or unauthenticated) caller — a common vector for credential theft.
 *
 * Compliant:
 *   management.endpoints.web.exposure.include=health,info
 *
 * Non-compliant:
 *   management.endpoints.web.exposure.include=*
 */
class InsecureActuatorExposureRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "InsecureActuatorExposure",
        severity = Severity.Security,
        description = "All actuator endpoints exposed — restrict to health and info",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        val exposureKey = "management.endpoints.web.exposure.include"
        val exposureValue = props.getProperty(exposureKey)
        if (exposureValue != null && "*" in exposureValue) {
            issues += exposureKey to "wildcard exposes heap dumps, env vars, and thread state — use health,info"
        }
        val secKey = "management.security.enabled"
        if (props.getProperty(secKey) == "false") {
            issues += secKey to "disables actuator security — remove or set to true"
        }
        return issues
    }
}
