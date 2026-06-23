package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A05 — Security Misconfiguration
// A very large max body size combined with no content-type restriction enables
// resource exhaustion and malicious file upload attacks via multipart.
// Compliant:   quarkus.http.limits.max-body-size=10M
// Non-compliant: quarkus.http.limits.max-body-size=500M (or very large value)
class QuarkusMultipartInsecureRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusMultipartInsecure",
        severity = Severity.Security,
        description = "Quarkus multipart upload limit is very large or unset — enforce a reasonable max-body-size",
        debt = Debt.TEN_MINS,
    )

    // Accepts an optional K/M/G binary-multiple suffix or a bare byte count.
    private val sizePattern = Regex("""^(\d+)\s*([KMG]?)$""", RegexOption.IGNORE_CASE)

    private val maxBodySizeMb: Int = config.valueOrDefault("maxBodySizeMb", 50)

    @Suppress("ReturnCount")
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "quarkus.http.limits.max-body-size"
        val rawValue = props.getProperty(key)
        // Unset key: Quarkus still accepts uploads (default ~10M), but an explicit limit
        // documents intent and protects against config drift — promised by the description.
        if (rawValue == null) {
            return listOf(key to "max-body-size is unset — set an explicit limit (e.g. 10M)")
        }
        val match = sizePattern.matchEntire(rawValue.trim()) ?: return emptyList()
        val size = match.groupValues[1].toLongOrNull() ?: return emptyList()
        val bytes = when (match.groupValues[2].uppercase()) {
            "G" -> size * 1024 * 1024 * 1024
            "M" -> size * 1024 * 1024
            "K" -> size * 1024
            else -> size // bare byte count
        }
        val maxBytes = maxBodySizeMb.toLong() * 1024 * 1024
        if (bytes <= maxBytes) return emptyList()
        return listOf(key to "max-body-size=$rawValue is very large — set a reasonable limit (e.g. 10M)")
    }
}
