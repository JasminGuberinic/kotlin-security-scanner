package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.DetectionPatterns.LOG_METHOD_NAMES
import com.jasmin.security.detekt.core.DetectionPatterns.SENSITIVE_LOG_KEYWORDS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateEntryWithExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE — OWASP A09
class SensitiveDataLoggingRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "SensitiveDataLogging",
        severity = Severity.Security,
        description = "Potential credential in log output — never log passwords, tokens, or secrets (OWASP A09)",
        debt = Debt.TWENTY_MINS
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.lowercase() ?: return
        if (callee !in LOG_METHOD_NAMES) return
        val args = expression.valueArguments.mapNotNull { it.getArgumentExpression() }
        if (args.isEmpty()) return

        val firstArg = args.first()
        // Interpolated message: only the interpolated ${expr} fragments are user data —
        // ignore the literal prose so "Reset of the password page for ${user.id}" is clean.
        if (firstArg is KtStringTemplateExpression &&
            firstArg.hasInterpolation() &&
            interpolationsAreSensitive(firstArg)
        ) {
            reportAt(expression, "Logging call may expose sensitive data — review variables being logged")
            return
        }

        // SLF4J parameterized form: log.info("password={}", userPwd) — first arg is a literal
        // template, the value arguments carry the data. Flag a sensitive identifier name there.
        if (args.drop(1).any { containsSensitiveKeyword(it.text) }) {
            reportAt(expression, "Logging call may expose sensitive data — review variables being logged")
        }
    }

    private fun interpolationsAreSensitive(template: KtStringTemplateExpression): Boolean =
        template.entries
            .filterIsInstance<KtStringTemplateEntryWithExpression>()
            .any { containsSensitiveKeyword(it.expression?.text ?: "") }

    private fun containsSensitiveKeyword(text: String) =
        SENSITIVE_LOG_KEYWORDS.any { text.lowercase().contains(it) }
}
