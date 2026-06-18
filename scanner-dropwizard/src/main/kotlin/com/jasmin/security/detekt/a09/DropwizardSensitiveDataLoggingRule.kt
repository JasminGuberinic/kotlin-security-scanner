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
// Logging sensitive field names (password, token, secret) in a JAX-RS application
// leaks credentials to log aggregators, log files, and anyone with log access.
// Compliant:   logger.info("User {} authenticated", userId)
// Non-compliant: logger.info("Token: {}", token)
class DropwizardSensitiveDataLoggingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardSensitiveDataLogging",
        severity = Severity.Security,
        description = "Log statement includes a sensitive field name — avoid logging credentials or tokens",
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
        reportAt(expression, "Log message references sensitive keyword — avoid logging credentials or tokens")
    }
}
