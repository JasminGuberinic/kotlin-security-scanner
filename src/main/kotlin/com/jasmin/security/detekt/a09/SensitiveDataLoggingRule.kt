package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.DetectionPatterns.LOG_METHOD_NAMES
import com.jasmin.security.detekt.core.DetectionPatterns.SENSITIVE_LOG_KEYWORDS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
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
        val message = firstStringArgument(expression) ?: return
        if (message.isLiteral()) return
        if (containsSensitiveKeyword(message.text)) {
            reportAt(expression, "Logging call may expose sensitive data — review variables being logged")
        }
    }

    private fun firstStringArgument(expression: KtCallExpression) =
        expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtStringTemplateExpression

    private fun containsSensitiveKeyword(text: String) =
        SENSITIVE_LOG_KEYWORDS.any { text.lowercase().contains(it) }
}
