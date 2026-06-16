package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE — OWASP A09
class SensitiveDataLoggingRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "SensitiveDataLogging",
        severity = Severity.Security,
        description = "Sensitive data may be written to logs — never log passwords, tokens, or secrets (OWASP A09)",
        debt = Debt.TWENTY_MINS
    )

    private val logMethods = setOf("trace", "debug", "info", "warn", "error", "log")

    private val sensitiveKeywords = setOf(
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "credential", "privatekey", "private_key", "accesskey", "access_key",
        "clientsecret", "client_secret", "authorization", "bearer"
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)

        val calleeName = expression.calleeExpression?.text?.lowercase() ?: return
        if (calleeName !in logMethods) return

        val args = expression.valueArguments
        if (args.isEmpty()) return

        val firstArg = args.first().getArgumentExpression() ?: return

        // Only flag string templates with interpolation (logging a variable)
        if (firstArg !is KtStringTemplateExpression) return
        if (!firstArg.hasInterpolation()) return

        val allText = firstArg.text.lowercase()

        val hasSensitiveKeyword = sensitiveKeywords.any { keyword ->
            allText.contains(keyword)
        }

        if (hasSensitiveKeyword) {
            report(
                CodeSmell(
                    issue,
                    Entity.from(expression),
                    "Logging call may expose sensitive data — review variables being logged"
                )
            )
        }
    }
}
