package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A01 — Broken Access Control
// deleteAll() removes every row in a table without a WHERE clause.
// A missing guard, a misrouted request, or a logic bug can wipe production data.
// Compliant:   Users.deleteWhere { Users.active eq false }
// Non-compliant: Users.deleteAll()
class KtorExposedDeleteAllRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorExposedDeleteAll",
        severity = Severity.Security,
        description = "deleteAll() removes every row without a WHERE clause — use deleteWhere{} with an explicit condition",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "deleteAll") return
        reportAt(
            expression,
            "deleteAll() deletes every row in the table — use deleteWhere { condition } to scope the deletion",
        )
    }
}
