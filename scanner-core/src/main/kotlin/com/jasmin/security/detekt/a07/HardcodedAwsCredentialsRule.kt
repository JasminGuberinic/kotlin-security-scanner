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
 * String literals matching the AWS access key ID format (AKIA/ASIA/AROA/AIDA
 * followed by 16 uppercase alphanumeric characters) are live credentials that
 * must be rotated immediately. Any commit containing them is effectively a breach
 * even after the key is revoked, because git history is permanent.
 *
 * Non-compliant:
 *   val key = "AKIAIOSFODNN7EXAMPLE"
 */
class HardcodedAwsCredentialsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedAwsCredentials",
        severity = Severity.Security,
        description = "Hardcoded AWS access key — rotate immediately and use IAM roles or env vars",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (DetectionPatterns.AWS_ACCESS_KEY_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "Hardcoded AWS access key detected — rotate immediately and use IAM roles or environment variables",
            )
        }
    }
}
