package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: PERMISSIVE_CORS — OWASP A05
class PermissiveCorsRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "PermissiveCors",
        severity = Severity.Security,
        description = "CORS allows all origins ('*') — restrict to known domains in production (OWASP A05)",
        debt = Debt.TWENTY_MINS
    )

    private val corsMethodNames = setOf("allowedOrigins", "allowedOriginPatterns", "addAllowedOrigin")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in corsMethodNames) return
        if (hasWildcardArgument(expression)) {
            reportAt(expression, "'$callee(\"*\")' allows any origin — restrict to explicit domains")
        }
    }

    private fun hasWildcardArgument(expression: KtCallExpression) =
        expression.valueArguments.any { arg ->
            val str = arg.getArgumentExpression() as? KtStringTemplateExpression ?: return@any false
            str.isLiteral() && str.rawValue() == "*"
        }
}
