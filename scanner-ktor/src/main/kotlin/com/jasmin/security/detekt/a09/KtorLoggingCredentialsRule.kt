package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A09 — Security Logging and Monitoring Failures
// Logging token/password/secret values to Ktor's application logger exposes credentials
// in log files and log aggregation systems accessible to many people.
// Compliant:   log.info("User {} authenticated", call.principal<UserPrincipal>()?.name)
// Non-compliant: log.info("Received token: $token")
class KtorLoggingCredentialsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorLoggingCredentials",
        severity = Severity.Security,
        description = "Log message references sensitive credential keyword — avoid logging tokens or passwords",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.LOG_METHOD_NAMES) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val msgTemplate = firstArg as? KtStringTemplateExpression ?: return
        val msgText = msgTemplate.text.lowercase()
        if (DetectionPatterns.SENSITIVE_LOG_KEYWORDS.none { it in msgText }) return
        reportAt(expression, "Log message references sensitive keyword — log user IDs, not credentials")
    }
}
