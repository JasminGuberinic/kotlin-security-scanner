package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A03 — Injection
// Kotlin Exposed exec() / addString() with string interpolation allows SQL injection.
// The DSL-based approach is safe; raw SQL strings with user input are not.
// Compliant:   Users.select { Users.name eq name }
// Non-compliant: exec("SELECT * FROM users WHERE name = '$name'")
class KtorExposedOrmInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorExposedOrmInjection",
        severity = Severity.Security,
        description = "Exposed exec() with interpolated SQL string — use the Exposed DSL or prepared statements",
        debt = Debt.TWENTY_MINS,
    )

    private val dangerousCalls = setOf("exec", "addString")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in dangerousCalls) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression || !firstArg.hasInterpolation()) return
        reportAt(
            expression,
            "$callee() with interpolated SQL — use Exposed DSL: Users.select { Users.id eq id }",
        )
    }
}
