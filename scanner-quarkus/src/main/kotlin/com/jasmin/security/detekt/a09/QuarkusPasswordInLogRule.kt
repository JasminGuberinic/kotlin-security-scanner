package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A09 — Security Logging and Monitoring Failures
// Logging password, token, secret, or key values creates a persistent plaintext
// copy in log files, often readable by anyone with server/log-aggregator access.
// Compliant:   Log.info("Login attempt for user $userId")
// Non-compliant: Log.debug("Authenticating with password=$password")
class QuarkusPasswordInLogRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusPasswordInLog",
        severity = Severity.Security,
        description = "Sensitive keyword in log message — credentials may be written to log files",
        debt = Debt.TEN_MINS,
    )

    private val logMethods = setOf("debug", "info", "warn", "error", "trace", "fatal")
    private val sensitiveKeywords = setOf("password", "passwd", "secret", "token", "apikey", "api_key", "credential")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in logMethods) return
        val dotExpr = expression.parent as? KtDotQualifiedExpression ?: return
        val receiver = dotExpr.receiverExpression.text.lowercase()
        if ("log" !in receiver && "logger" !in receiver) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression) return
        val msgText = firstArg.text.lowercase()
        if (sensitiveKeywords.none { it in msgText }) return
        reportAt(
            expression,
            "Log message contains sensitive keyword — remove credentials from log statements",
        )
    }
}
