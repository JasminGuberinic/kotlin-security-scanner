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
 * OWASP A03 — Injection (Expression Language)
 * FindSecBugs: EL_INJECTION
 *
 * Flags ELProcessor.eval() and ExpressionFactory.createValueExpression() calls
 * where the expression string is not a literal. An attacker-supplied EL expression
 * can call arbitrary Java methods, read system properties, or execute OS commands.
 *
 * Compliant:
 *   processor.eval("user.name")               // literal — safe
 *
 * Non-compliant:
 *   processor.eval(userInput)                 // variable — EL injection
 *   factory.createValueExpression(ctx, expr, String::class.java)  // dynamic expr
 */
class ELInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ELInjection",
        severity = Severity.Security,
        description = "EL expression from non-literal input — attacker-supplied EL can invoke arbitrary code",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.EL_EVAL_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (!isSafe) {
            reportAt(
                expression,
                "$callee() with dynamic EL expression — use a sandbox or literal expressions only",
            )
        }
    }
}
