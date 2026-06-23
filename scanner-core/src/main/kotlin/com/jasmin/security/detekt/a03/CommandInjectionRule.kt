package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtExpression
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
            val e = arg.getArgumentExpression() ?: return@any false
            // Flag any non-literal argument: interpolated templates AND bare variables /
            // expressions (e.g. exec(userInput)). A plain string literal is safe.
            isNonLiteral(e)
        }
    }

    @Suppress("ReturnCount")
    private fun isProcessBuilderWithVariable(expression: KtCallExpression): Boolean {
        if (expression.calleeExpression?.text != DetectionPatterns.PROCESS_BUILDER_CLASS) return false
        return expression.valueArguments.any { arg ->
            val e = arg.getArgumentExpression() ?: return@any false
            // listOf(...)/arrayOf(...) — a collection of pure string literals is safe;
            // flag only if some element is non-literal.
            if (e is KtCallExpression && e.calleeExpression?.text in COLLECTION_BUILDERS) {
                e.valueArguments.any { el ->
                    val ee = el.getArgumentExpression() ?: return@any false
                    isNonLiteral(ee)
                }
            } else {
                isNonLiteral(e)
            }
        }
    }

    /** True unless the expression is a plain (non-interpolated) string literal. */
    private fun isNonLiteral(e: KtExpression): Boolean =
        e !is KtStringTemplateExpression || e.hasInterpolation()

    private companion object {
        val COLLECTION_BUILDERS = setOf("listOf", "arrayOf", "mutableListOf", "arrayListOf")
    }
}
