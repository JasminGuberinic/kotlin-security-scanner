package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (HTTP Response Splitting)
 * FindSecBugs: HTTP_RESPONSE_SPLITTING
 *
 * Flags addHeader/setHeader calls where the value argument is dynamic (not a string
 * literal). A carriage-return / line-feed in the value lets an attacker inject
 * arbitrary response headers or split the HTTP response into two.
 *
 * Compliant:
 *   response.setHeader("Cache-Control", "no-store")  // literal value — safe
 *
 * Non-compliant:
 *   response.addHeader("X-Custom", userInput)         // dynamic — strip CR/LF first
 *   response.setHeader("Location", "https://${'$'}host")  // interpolated
 */
class ResponseSplittingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ResponseSplitting",
        severity = Severity.Security,
        description = "HTTP header value from dynamic input — CR/LF in the value enables response splitting",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.HTTP_HEADER_SETTER_METHODS) return
        val valueArg = expression.valueArguments.getOrNull(1)?.getArgumentExpression() ?: return
        val isSafe = valueArg is KtStringTemplateExpression && !valueArg.hasInterpolation()
        if (!isSafe) {
            reportAt(
                expression,
                "Header value in $callee() is dynamic — strip \\r and \\n before setting the header",
            )
        }
    }
}
