package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A05 — Security Misconfiguration (Cleartext Transport)
 *
 * Explicitly setting spring.kafka.*.security.protocol=PLAINTEXT means all
 * Kafka traffic — messages, offsets, and credentials — travels unencrypted.
 * Any network observer on the broker path can read or inject messages.
 *
 * Compliant:
 *   spring.kafka.security.protocol=SASL_SSL
 *   spring.kafka.security.protocol=SSL
 *
 * Non-compliant:
 *   spring.kafka.security.protocol=PLAINTEXT
 */
class KafkaInsecureProtocolRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "KafkaInsecureProtocol",
        severity = Severity.Security,
        description = "Kafka security protocol set to PLAINTEXT — all broker traffic is unencrypted",
        debt = Debt.TWENTY_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if (!key.startsWith("spring.kafka.") || !key.endsWith("security.protocol")) return@forEach
            if (value != "PLAINTEXT") return@forEach
            issues += key to "Kafka transport is unencrypted — use SASL_SSL or SSL"
        }
        return issues
    }
}
