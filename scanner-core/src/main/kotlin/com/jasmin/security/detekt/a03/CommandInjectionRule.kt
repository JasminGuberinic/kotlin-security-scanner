package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection
 * FindSecBugs: COMMAND_INJECTION
 *
 * Flags OS command execution when any argument is a variable or interpolated string.
 * Runtime.exec() and ProcessBuilder accept user-controlled strings directly,
 * enabling arbitrary command execution.
 *
 * Compliant:
 *   Runtime.getRuntime().exec(arrayOf("ls", "-l", "/tmp"))  // all literals
 *
 * Non-compliant:
 *   Runtime.getRuntime().exec("ls $userInput")
 *   ProcessBuilder(listOf("sh", "-c", userInput))
 */
class CommandInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "CommandInjection",
        severity = Severity.Security,
        description = "OS command executed with non-literal argument — user input may reach the shell",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (isExecWithVariable(expression) || isProcessBuilderWithVariable(expression)) {
            reportAt(
                expression,
                "Command argument is not a literal — use an allowlist before passing to exec/ProcessBuilder",
            )
        }
    }

    private fun isExecWithVariable(expression: KtCallExpression): Boolean {
        if (expression.calleeExpression?.text !in DetectionPatterns.COMMAND_EXEC_METHODS) return false
        return expression.valueArguments.any { arg ->
            val e = arg.getArgumentExpression()
            e is KtStringTemplateExpression && e.hasInterpolation()
        }
    }

    @Suppress("ReturnCount")
    private fun isProcessBuilderWithVariable(expression: KtCallExpression): Boolean {
        if (expression.calleeExpression?.text != DetectionPatterns.PROCESS_BUILDER_CLASS) return false
        return expression.valueArguments.any { arg ->
            val e = arg.getArgumentExpression()
            e !is KtStringTemplateExpression || e.hasInterpolation()
        }
    }
}
