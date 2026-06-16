package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

class SqlInjectionRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "SqlInjection",
        severity = Severity.Security,
        description = "Possible SQL injection — use parameterized queries or Spring Data @Query with :params",
        debt = Debt.TWENTY_MINS
    )

    private val sqlKeywords = listOf("SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN")

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (!expression.hasInterpolation()) return
        val text = expression.text.uppercase()
        if (sqlKeywords.none { text.contains(it) }) return
        report(
            CodeSmell(
                issue,
                Entity.from(expression),
                "String interpolation in SQL query is vulnerable to SQL injection — use named parameters"
            )
        )
    }

    @Suppress("ReturnCount")
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        if (expression.operationReference.text != "+") return
        val left = expression.left?.text?.uppercase() ?: return
        if (sqlKeywords.none { left.contains(it) }) return
        if (expression.right is KtStringTemplateExpression) return
        report(
            CodeSmell(
                issue,
                Entity.from(expression),
                "String concatenation in SQL query is vulnerable to SQL injection — use named parameters"
            )
        )
    }
}
