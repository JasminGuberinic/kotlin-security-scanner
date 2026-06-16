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
 * OWASP A03 — Injection (Groovy / ScriptEngine)
 * FindSecBugs: GROOVY_SHELL
 *
 * Flags GroovyShell.evaluate() and ScriptEngine.eval() calls where the script
 * argument is not a string literal. Executing attacker-supplied Groovy or script
 * engine code enables arbitrary code execution on the JVM host.
 *
 * Compliant:
 *   shell.evaluate("println 'hello'")          // literal — safe
 *
 * Non-compliant:
 *   shell.evaluate(userScript)                 // variable — RCE risk
 *   engine.eval("println '${'$'}userInput'")   // interpolated — RCE risk
 */
class GroovyScriptInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "GroovyScriptInjection",
        severity = Severity.Security,
        description = "Script execution with non-literal source — user-controlled scripts enable RCE",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.SCRIPT_EVAL_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (!isSafe) {
            reportAt(
                expression,
                "$callee() with dynamic script source — never pass user input to a script engine",
            )
        }
    }
}
