package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 *
 * Slack tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-) grant access to a workspace's
 * messages and channels. A hardcoded token is a live credential that must be
 * revoked in the Slack app settings the moment it lands in source control.
 *
 * Non-compliant:
 *   val token = "xoxb-<workspace-id>-<token-body>"
 */
class SlackTokenRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SlackToken",
        severity = Severity.Security,
        description = "Hardcoded Slack token — revoke it and load from environment or a secret manager",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (DetectionPatterns.SLACK_TOKEN_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "Hardcoded Slack token detected — revoke it and load from environment or a secret manager",
            )
        }
    }
}
