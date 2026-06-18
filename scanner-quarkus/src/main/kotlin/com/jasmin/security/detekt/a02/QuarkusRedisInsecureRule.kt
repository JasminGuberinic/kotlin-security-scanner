package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A02 — Cryptographic Failures
// quarkus.redis.hosts with redis:// transmits data and credentials in cleartext.
// Compliant:   quarkus.redis.hosts=rediss://redis:6380
// Non-compliant: quarkus.redis.hosts=redis://redis:6379
class QuarkusRedisInsecureRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusRedisInsecure",
        severity = Severity.Security,
        description = "Quarkus Redis uses unencrypted redis:// — switch to rediss:// for TLS",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if (key.contains("quarkus.redis") && key.endsWith(".hosts") && value.startsWith("redis://")) {
                issues += key to "Redis connection uses redis:// — switch to rediss:// for TLS-encrypted traffic"
            }
        }
        return issues
    }
}
