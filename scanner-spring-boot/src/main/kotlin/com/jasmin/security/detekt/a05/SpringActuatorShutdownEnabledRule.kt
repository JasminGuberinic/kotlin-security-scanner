package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

class SpringActuatorShutdownEnabledRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "SpringActuatorShutdownEnabled",
        severity = Severity.Security,
        description = "Actuator shutdown endpoint enabled — allows remote JVM termination via HTTP POST",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        val shutdownKey = "management.endpoint.shutdown.enabled"
        if (props.getProperty(shutdownKey) == "true") {
            issues += shutdownKey to "Shutdown endpoint enabled — any unauthenticated caller can stop the JVM"
        }
        val exposeKey = "management.endpoints.web.exposure.include"
        val exposed = props.getProperty(exposeKey) ?: ""
        if ("shutdown" in exposed) {
            issues += exposeKey to "Shutdown endpoint exposed — remove 'shutdown' from the exposure list"
        }
        return issues
    }
}
