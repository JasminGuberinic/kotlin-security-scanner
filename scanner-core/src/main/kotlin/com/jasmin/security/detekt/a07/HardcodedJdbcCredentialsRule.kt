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
 * A JDBC URL that embeds the database username and password — either as
 * user:pass@host or via ?password=/&user= query parameters — bakes the credential
 * into source and into every connection-string log line. Pass credentials
 * separately and inject the secret from the environment.
 *
 * Non-compliant:
 *   "jdbc:postgresql://admin:s3cr3t@db.internal:5432/app"
 *   "jdbc:mysql://db/app?user=root&password=hunter2"
 */
class HardcodedJdbcCredentialsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedJdbcCredentials",
        severity = Severity.Security,
        description = "JDBC URL embeds credentials — inject the password from the environment instead",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (!text.contains("jdbc:", ignoreCase = true)) return
        if (DetectionPatterns.JDBC_CREDENTIAL_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "JDBC URL embeds a credential — pass user/password separately and inject the secret from the environment",
            )
        }
    }
}
