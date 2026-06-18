package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A05 — Security Misconfiguration
// A very high max form data size in the Dropwizard HTTP connector enables
// resource-exhaustion attacks by uploading enormous request bodies.
// Compliant:   server.maxRequestEntitySize=10MiB
// Non-compliant: server.maxRequestEntitySize=500MiB
class DropwizardInsecureMultipartRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardInsecureMultipart",
        severity = Severity.Security,
        description = "Dropwizard maxRequestEntitySize is very large — limits resource exhaustion protection",
        debt = Debt.TEN_MINS,
    )

    private val largePattern = Regex("""^(\d+)\s*(GiB|GiB|GB|MiB|MB)$""", RegexOption.IGNORE_CASE)

    @Suppress("MagicNumber")
    private val maxSafeMib = 50

    @Suppress("MagicNumber", "ReturnCount")
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "server.maxRequestEntitySize"
        val value = props.getProperty(key) ?: return emptyList()
        val match = largePattern.matchEntire(value.trim()) ?: return emptyList()
        val size = match.groupValues[1].toLongOrNull() ?: return emptyList()
        val unit = match.groupValues[2].uppercase()
        val mib = if ("G" in unit) size * 1024 else size
        if (mib <= maxSafeMib) return emptyList()
        return listOf(key to "maxRequestEntitySize=$value is very large — set a reasonable limit (e.g. 10MiB)")
    }
}
