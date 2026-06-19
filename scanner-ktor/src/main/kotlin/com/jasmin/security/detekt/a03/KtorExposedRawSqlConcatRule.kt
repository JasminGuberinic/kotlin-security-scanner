package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A03 — Injection
// exec() with string concatenation is equivalent to exec() with interpolation:
// both splice unsanitised input directly into a SQL string.
// KtorExposedOrmInjectionRule catches template literals ("...$var...").
// This rule catches classic concatenation: "SELECT ... WHERE id = " + id
// Compliant:   Users.select { Users.id eq id }
// Non-compliant: exec("SELECT * FROM users WHERE id = " + id)
class KtorExposedRawSqlConcatRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorExposedRawSqlConcat",
        severity = Severity.Security,
        description = "exec() with string concatenation — SQL injection risk; use Exposed DSL or prepared statements",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "exec") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtBinaryExpression) return
        if (firstArg.operationToken != KtTokens.PLUS) return
        reportAt(
            expression,
            "exec() with concatenated SQL string — use Exposed DSL: Users.select { Users.id eq id }",
        )
    }
}
