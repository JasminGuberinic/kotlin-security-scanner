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

    private val largeBodyPattern = Regex("""^(\d+)\s*([GM])$""", RegexOption.IGNORE_CASE)

    @Suppress("MagicNumber")
    private val maxSafeMegabytes = 50

    @Suppress("MagicNumber")
    private val megabytesPerGigabyte = 1024

    @Suppress("ReturnCount")
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "quarkus.http.limits.max-body-size"
        val value = props.getProperty(key) ?: return emptyList()
        val match = largeBodyPattern.matchEntire(value.trim()) ?: return emptyList()
        val size = match.groupValues[1].toLongOrNull() ?: return emptyList()
        val unit = match.groupValues[2].uppercase()
        val megabytes = if (unit == "G") size * megabytesPerGigabyte else size
        if (megabytes <= maxSafeMegabytes) return emptyList()
        return listOf(key to "max-body-size=$value is very large — set a reasonable limit (e.g. 10M)")
    }
}
