package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// OWASP A05 — Security Misconfiguration
// SchemaUtils.create/drop in application boot code runs DDL on every startup.
// Exposes the schema structure via error messages and risks data loss on drop.
// Compliant:   use database migrations (Flyway/Liquibase) in a dedicated migration step
// Non-compliant: SchemaUtils.create(Users, Orders) in Application.module()
class KtorExposedSchemaAutoCreateRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorExposedSchemaAutoCreate",
        severity = Severity.Security,
        description = "SchemaUtils.create/drop in application code — use Flyway or Liquibase migrations instead",
        debt = Debt.TWENTY_MINS,
    )

    private val dangerousMethods = setOf("create", "drop", "createMissingTablesAndColumns", "dropDatabase")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in dangerousMethods) return
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        if (parent.receiverExpression.text != "SchemaUtils") return
        reportAt(
            expression,
            "SchemaUtils.$callee() in application code — replace with versioned migrations (Flyway/Liquibase)",
        )
    }
}
