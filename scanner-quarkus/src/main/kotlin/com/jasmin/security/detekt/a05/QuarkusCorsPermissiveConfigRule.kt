package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A05 — Security Misconfiguration
 * quarkus.http.cors.origins=* allows any origin to make cross-origin requests,
 * enabling CSRF and data-exfiltration from authenticated sessions.
 */
class QuarkusCorsPermissiveConfigRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusCorsPermissiveConfig",
        severity = Severity.Security,
        description = "quarkus.http.cors.origins=* allows all origins — restrict to specific domains",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "quarkus.http.cors.origins"
        val value = props.getProperty(key)?.trim() ?: return emptyList()
        return if (value == "*" || value == ".*") {
            listOf(key to "CORS allows all origins — replace * with specific allowed domains")
        } else {
            emptyList()
        }
    }
}
