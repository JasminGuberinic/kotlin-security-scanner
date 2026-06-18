package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A02 — Cryptographic Failures
// mongodb:// transmits all data without TLS. Use mongodb+srv:// or set tls=true.
// Compliant:   quarkus.mongodb.connection-string=mongodb+srv://host/db?tls=true
// Non-compliant: quarkus.mongodb.connection-string=mongodb://host/db
class QuarkusMongoInsecureRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusMongoInsecure",
        severity = Severity.Security,
        description = "Quarkus MongoDB uses mongodb:// without TLS — append ?tls=true or use mongodb+srv://",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            val isMongoConnectionString = "quarkus.mongodb" in key && "connection-string" in key
            val isInsecure = value.startsWith("mongodb://") && "tls=true" !in value
            if (isMongoConnectionString && isInsecure) {
                issues += key to "MongoDB connection without TLS — use mongodb+srv:// or append ?tls=true"
            }
        }
        return issues
    }
}
