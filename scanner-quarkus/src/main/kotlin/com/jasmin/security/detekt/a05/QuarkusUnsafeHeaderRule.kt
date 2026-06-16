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
 * OWASP A05 — Security Misconfiguration (Unsafe Response Header in JAX-RS)
 * FindSecBugs: HTTP_RESPONSE_SPLITTING
 *
 * Flags JAX-RS Response builder .header() calls where the value argument is not
 * a string literal. Dynamic header values may contain CR/LF characters enabling
 * HTTP response splitting, or allow Content-Type sniffing when derived from input.
 *
 * Compliant:
 *   Response.ok().header("X-Frame-Options", "DENY").build()   // literal — safe
 *
 * Non-compliant:
 *   Response.ok().header("Content-Type", userInput).build()   // dynamic — unsafe
 */
class QuarkusUnsafeHeaderRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusUnsafeHeader",
        severity = Severity.Security,
        description = "JAX-RS Response.header() with dynamic value — CR/LF enables response splitting",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "header") return
        val parentDot = expression.parent as? KtDotQualifiedExpression ?: return
        if (!parentDot.receiverExpression.text.contains("Response")) return
        val valueArg = expression.valueArguments.getOrNull(1)?.getArgumentExpression() ?: return
        val isSafe = valueArg is KtStringTemplateExpression && !valueArg.hasInterpolation()
        if (!isSafe) {
            reportAt(
                expression,
                "Response.header() with dynamic value — strip \\r\\n or use a literal header value",
            )
        }
    }
}
