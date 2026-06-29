package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A05 — Security Misconfiguration (Permissive CORS / CWE-942)
 *
 * Vert.x-Web's `CorsHandler.create(".*")` (or `addRelativeOrigin(".*")` / `addOrigin("*")`)
 * allows any origin to make cross-origin requests. Vert.x uses its own CORS API, so this is
 * not caught by the generic CorsConfiguration rule. Allow only trusted origins.
 *
 * Non-compliant:
 *   router.route().handler(CorsHandler.create(".*"))
 *   CorsHandler.create().addOrigin("*")
 */
class VertxCorsWildcardRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxCorsWildcard",
        severity = Severity.Security,
        description = "Vert.x CorsHandler allows any origin (\".*\"/\"*\") — restrict to trusted origins",
        debt = Debt.TWENTY_MINS,
    )

    private val originMethods = setOf("addOrigin", "addRelativeOrigin")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        if (arg.hasInterpolation()) return
        val value = arg.rawValue()
        if (value != "*" && value != ".*") return

        val isCorsCreate = callee == "create" &&
            (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text?.substringAfterLast(".") == "CorsHandler"
        if (isCorsCreate || callee in originMethods) {
            reportAt(
                expression,
                "Vert.x CORS $callee(\"$value\") allows any origin — list trusted origins with addOrigin(\"https://app.example.com\")",
            )
        }
    }
}
