package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtExpression
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
        // createValueExpression(elContext, expression, expectedType) — EL string is arg[1].
        // eval(expression) — EL string is arg[0].
        val elArgIndex = if (callee == "createValueExpression") 1 else 0
        val elArg = expression.valueArguments.getOrNull(elArgIndex)?.getArgumentExpression() ?: return
        val isSafe = isConstantString(elArg)
        if (!isSafe) {
            reportAt(
                expression,
                "$callee() with dynamic EL expression — use a sandbox or literal expressions only",
            )
        }
    }

    // A bare non-interpolated string literal OR a '+' concatenation of constant strings is safe.
    private fun isConstantString(expr: KtExpression): Boolean = when (expr) {
        is KtStringTemplateExpression -> !expr.hasInterpolation()
        is KtBinaryExpression -> {
            val left = expr.left
            val right = expr.right
            left != null && right != null &&
                isConstantString(left) && isConstantString(right)
        }
        else -> false
    }
}
