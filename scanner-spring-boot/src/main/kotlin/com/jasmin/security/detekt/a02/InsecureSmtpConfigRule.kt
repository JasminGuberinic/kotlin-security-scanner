package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

/**
 * OWASP A02 — Cryptographic Failures
 *
 * Disabling STARTTLS or SSL for SMTP sends email credentials and message
 * content in cleartext across the network.
 *
 * Compliant:
 *   spring.mail.properties.mail.smtp.starttls.enable=true
 *
 * Non-compliant:
 *   spring.mail.properties.mail.smtp.starttls.enable=false
 *   spring.mail.properties.mail.smtp.ssl.enable=false
 */
class InsecureSmtpConfigRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "InsecureSmtpConfig",
        severity = Severity.Security,
        description = "SMTP configured without TLS — credentials and content sent in cleartext",
        debt = Debt.TEN_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        val starttlsKey = "spring.mail.properties.mail.smtp.starttls.enable"
        if (props.getProperty(starttlsKey) == "false") {
            issues += starttlsKey to "STARTTLS disabled — SMTP session is unencrypted"
        }
        val sslKey = "spring.mail.properties.mail.smtp.ssl.enable"
        if (props.getProperty(sslKey) == "false") {
            issues += sslKey to "SSL disabled — SMTP session is unencrypted"
        }
        return issues
    }
}
