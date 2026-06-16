package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns.FILE_CONSTRUCTORS
import com.jasmin.security.detekt.core.DetectionPatterns.PATH_METHODS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: PATH_TRAVERSAL_IN, PATH_TRAVERSAL_OUT — OWASP A03
class PathTraversalRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "PathTraversal",
        severity = Severity.Security,
        description = "File path built with a variable — sanitize and validate user-supplied paths (OWASP A03)",
        debt = Debt.TWENTY_MINS
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (isLiteralString(firstArg)) return

        when {
            callee in FILE_CONSTRUCTORS ->
                reportAt(expression, "'$callee' called with a non-literal path — validate input")
            isPathsCall(callee, expression) ->
                reportAt(expression, "Path built with a non-literal argument — validate input")
        }
    }

    private fun isLiteralString(arg: KtExpression) =
        arg is KtStringTemplateExpression && arg.isLiteral()

    @Suppress("ReturnCount")
    private fun isPathsCall(callee: String, expression: KtCallExpression): Boolean {
        if (callee !in PATH_METHODS) return false
        val parentText = expression.parent?.text ?: return false
        return parentText.startsWith("Paths.") || parentText.startsWith("Path.")
    }
}
