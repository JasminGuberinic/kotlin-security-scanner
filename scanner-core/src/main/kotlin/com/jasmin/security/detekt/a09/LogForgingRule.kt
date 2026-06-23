package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBlockStringTemplateEntry
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtSimpleNameStringTemplateEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A09 — Security Logging and Monitoring Failures (Log Forging / CWE-117)
 *
 * Interpolating request-derived input straight into a log message lets an attacker
 * embed CR/LF and forge additional log lines — corrupting audit trails and, with
 * some log viewers, injecting markup. Strip line breaks (or use structured logging
 * with parameters) before logging external input.
 *
 * Compliant:
 *   log.info("path={}", request.path.replace("[\r\n]".toRegex(), "_"))
 *
 * Non-compliant:
 *   log.info("Requested path: ${'$'}{request.path}")
 */
class LogForgingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "LogForging",
        severity = Severity.Security,
        description = "Request input logged unsanitized — strip CR/LF to prevent forged log entries",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee !in DetectionPatterns.LOG_METHOD_NAMES) return
        val hasForgeableInput = expression.valueArguments.any { arg ->
            val template = arg.getArgumentExpression() as? KtStringTemplateExpression ?: return@any false
            template.hasInterpolation() && template.entries.any { entry ->
                val ref = when (entry) {
                    is KtSimpleNameStringTemplateEntry -> entry.text     // $request
                    is KtBlockStringTemplateEntry -> entry.text          // ${request.path}
                    else -> return@any false
                }.lowercase()
                DetectionPatterns.LOG_INPUT_KEYWORDS.any { it in ref }
            }
        }
        if (hasForgeableInput) {
            reportAt(
                expression,
                "Request input interpolated into a log message — strip CR/LF or use parameterized logging to prevent log forging",
            )
        }
    }
}
