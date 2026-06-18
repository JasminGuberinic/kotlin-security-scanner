package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A03 — Injection
// JDBI @SqlQuery/@SqlUpdate with string interpolation builds queries dynamically,
// enabling SQL injection. Use :paramName or <bindParam> placeholders instead.
// Compliant:   @SqlQuery("SELECT * FROM users WHERE id = :id")
// Non-compliant: @SqlQuery("SELECT * FROM users WHERE name = '$name'")
class DropwizardJdbiSqlInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardJdbiSqlInjection",
        severity = Severity.Security,
        description = "JDBI @SqlQuery/@SqlUpdate with interpolated string — use named bind parameters",
        debt = Debt.TWENTY_MINS,
    )

    private val jdbiAnnotations = setOf("SqlQuery", "SqlUpdate", "SqlCall", "SqlBatch")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val jdbiAnnotation = function.annotationEntries
            .find { it.shortName?.asString() in jdbiAnnotations } ?: return
        val sqlString = extractSqlString(jdbiAnnotation) ?: return
        if (!sqlString.hasInterpolation()) return
        reportAt(function, "JDBI SQL string with interpolation — use :paramName bind parameters")
    }

    private fun extractSqlString(annotation: KtAnnotationEntry): KtStringTemplateExpression? =
        annotation.valueArguments
            .firstOrNull()
            ?.getArgumentExpression() as? KtStringTemplateExpression
}
