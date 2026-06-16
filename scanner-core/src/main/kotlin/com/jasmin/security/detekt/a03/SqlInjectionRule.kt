package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns.SQL_KEYWORDS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: SQL_INJECTION_JPA, SQL_INJECTION_SPRING_JDBC — OWASP A03
class SqlInjectionRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "SqlInjection",
        severity = Severity.Security,
        description = "SQL built with string interpolation or concatenation — use named parameters (e.g. :param)",
        debt = Debt.TWENTY_MINS
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.isLiteral()) return
        if (containsSqlKeyword(expression.text)) {
            reportAt(expression, "String interpolation in SQL query — use :namedParam or ? placeholders")
        }
    }

    @Suppress("ReturnCount")
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        if (expression.operationReference.text != "+") return
        val leftText = expression.left?.text?.uppercase() ?: return
        if (!containsSqlKeyword(leftText)) return
        if (expression.right is KtStringTemplateExpression) return
        reportAt(expression, "String concatenation in SQL query — use :namedParam or ? placeholders")
    }

    private fun containsSqlKeyword(text: String) = SQL_KEYWORDS.any { text.uppercase().contains(it) }
}
