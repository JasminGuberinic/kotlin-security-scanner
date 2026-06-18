package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A08 — Software and Data Integrity (Deserialization)
 * CVE-2023-34040 — Spring Kafka trusted packages wildcard
 *
 * Setting spring.json.trusted.packages=* allows the Kafka consumer to
 * deserialize any Java class embedded in the message header. An attacker
 * who can produce to the topic can trigger arbitrary class instantiation,
 * potentially leading to RCE via gadget chains.
 *
 * Compliant:
 *   spring.kafka.consumer.properties.spring.json.trusted.packages=com.myapp.dto
 *
 * Non-compliant:
 *   spring.kafka.consumer.properties.spring.json.trusted.packages=*
 */
class KafkaTrustedPackagesWildcardRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "KafkaTrustedPackagesWildcard",
        severity = Severity.Security,
        description = "Kafka trusted packages '*' enables arbitrary deserialization (CVE-2023-34040)",
        debt = Debt.TWENTY_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if ("trusted.packages" !in key) return@forEach
            if (value != "*") return@forEach
            issues += key to "Wildcard trusted packages — list exact packages: com.myapp.dto,com.myapp.event"
        }
        return issues
    }
}
