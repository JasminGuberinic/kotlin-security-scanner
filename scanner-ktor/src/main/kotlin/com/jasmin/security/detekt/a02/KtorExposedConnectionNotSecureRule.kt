package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A02 — Cryptographic Failures
// Database.connect() with an SSL-disabled URL transmits credentials and data in plaintext.
// Common JDBC parameters that disable SSL: useSSL=false, ssl=false, sslmode=disable
// Compliant:   Database.connect("jdbc:postgresql://host/db?ssl=true&sslmode=require", ...)
// Non-compliant: Database.connect("jdbc:postgresql://host/db?useSSL=false", ...)
class KtorExposedConnectionNotSecureRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorExposedConnectionNotSecure",
        severity = Severity.Security,
        description = "Database.connect() with SSL disabled in JDBC URL — transmits data in plaintext",
        debt = Debt.TWENTY_MINS,
    )

    private val insecureSslParams = listOf("useSSL=false", "ssl=false", "sslmode=disable", "useSsl=false")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "connect") return
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        if (parent.receiverExpression.text.substringAfterLast(".") != "Database") return
        val hasInsecureUrl = expression.valueArguments.any { arg ->
            val argExpr = arg.getArgumentExpression()
            argExpr is KtStringTemplateExpression &&
                insecureSslParams.any { param -> argExpr.text.contains(param, ignoreCase = true) }
        }
        if (!hasInsecureUrl) return
        reportAt(
            expression,
            "Database.connect() with SSL disabled — add ssl=true&sslmode=require to the JDBC URL",
        )
    }
}
