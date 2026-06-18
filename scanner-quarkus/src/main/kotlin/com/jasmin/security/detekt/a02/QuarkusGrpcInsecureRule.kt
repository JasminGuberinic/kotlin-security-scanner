package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A02 — Cryptographic Failures
// gRPC clients connecting over plaintext expose RPC calls and credentials.
// Compliant:   quarkus.grpc.clients.my-service.ssl.trust-certificate=ca.pem
// Non-compliant: quarkus.grpc.clients.my-service.plain-text=true
class QuarkusGrpcInsecureRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusGrpcInsecure",
        severity = Severity.Security,
        description = "Quarkus gRPC client configured with plain-text=true — RPC traffic is unencrypted",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if ("quarkus.grpc.clients" in key && key.endsWith("plain-text") && value == "true") {
                issues += key to "gRPC client plain-text=true — configure TLS with ssl.trust-certificate"
            }
        }
        return issues
    }
}
