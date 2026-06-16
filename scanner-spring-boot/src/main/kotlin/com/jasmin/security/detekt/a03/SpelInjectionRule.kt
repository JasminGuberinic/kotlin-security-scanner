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
 * OWASP A03 — Injection (Spring Expression Language)
 * FindSecBugs: SPEL_INJECTION
 *
 * Flags SpelExpressionParser.parseExpression() / parseRaw() calls where the
 * expression argument is not a string literal. Evaluating user-controlled SpEL
 * expressions enables remote code execution via bean access and reflection.
 *
 * Compliant:
 *   parser.parseExpression("user.name")         // literal — safe
 *
 * Non-compliant:
 *   parser.parseExpression(userInput)           // variable — RCE risk
 *   parser.parseExpression("prefix_$userInput") // interpolated — RCE risk
 */
class SpelInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpelInjection",
        severity = Severity.Security,
        description = "SpEL expression built from non-literal input enables remote code execution",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (!isSpelParseCall(expression)) return
        if (hasNonLiteralArg(expression)) {
            reportAt(
                expression,
                "parseExpression() receives a non-literal — never evaluate user-controlled SpEL expressions",
            )
        }
    }

    private fun isSpelParseCall(expression: KtCallExpression) =
        expression.calleeExpression?.text in DetectionPatterns.SPEL_PARSER_METHODS

    private fun hasNonLiteralArg(expression: KtCallExpression): Boolean {
        val first = expression.valueArguments.firstOrNull()
            ?.getArgumentExpression() ?: return true
        return first !is KtStringTemplateExpression ||
            (first as KtStringTemplateExpression).hasInterpolation()
    }
}
