package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A07 — Identification and Authentication Failures
// Database.connect(url, password="literal") embeds database credentials in source code.
// Compliant:   Database.connect(url, password = System.getenv("DB_PASS") ?: error("not set"))
// Non-compliant: Database.connect("jdbc:...", "org.postgresql.Driver", "user", "hardcoded-pass")
class KtorHardcodedDatabasePasswordRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorHardcodedDatabasePassword",
        severity = Severity.Security,
        description = "Database.connect() with hardcoded password — use environment variable",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount", "MagicNumber")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        // PSI: Database.connect(...) is KtDotQualifiedExpression — callee is "connect", receiver is "Database"
        if (expression.calleeExpression?.text != "connect") return
        val dotExpr = expression.parent as? KtDotQualifiedExpression ?: return
        if (dotExpr.receiverExpression.text != "Database") return
        val args = expression.valueArguments
        // 4-arg form: connect(url, driver, user, password)
        if (args.size >= 4) {
            val passwordArg = args[3].getArgumentExpression()
            if (passwordArg is KtStringTemplateExpression && !passwordArg.hasInterpolation()) {
                val value = passwordArg.text.trim('"')
                if (value.isNotBlank()) {
                    reportAt(dotExpr, "Database.connect() with hardcoded password — use System.getenv(\"DB_PASS\")")
                    return
                }
            }
        }
        // Named password argument
        val passwordNamedArg = args.find { it.getArgumentName()?.asName?.asString() == "password" }
        val passwordExpr = passwordNamedArg?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        if (passwordExpr.hasInterpolation()) return
        val value = passwordExpr.text.trim('"')
        if (value.isBlank()) return
        reportAt(dotExpr, "Database.connect() with hardcoded password — use System.getenv(\"DB_PASS\")")
    }
}
