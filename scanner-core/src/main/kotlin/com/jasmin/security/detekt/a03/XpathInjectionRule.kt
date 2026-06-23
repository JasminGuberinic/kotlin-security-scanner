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
 * OWASP A03 — Injection (XPath)
 * FindSecBugs: XPATH_INJECTION
 *
 * Flags XPath methods (evaluate, selectNodes) called with an interpolated string.
 * User input in an XPath expression can alter the query logic, leaking data or
 * bypassing authentication checks in XML-based access control.
 *
 * Compliant:
 *   val expr = xpath.compile("//user[@id=${'$'}userId]")  // use XPathVariableResolver
 *
 * Non-compliant:
 *   xpath.evaluate("//user[@name='${'$'}name']", doc, XPathConstants.NODE)       // interpolated
 *   xpath.evaluate("//user[@name='" + name + "']", doc, XPathConstants.NODE)   // concatenated
 */
class XpathInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "XpathInjection",
        severity = Severity.Security,
        description = "XPath expression with interpolated input — sanitise or use XPathVariableResolver",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.XPATH_EXPRESSION_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val dynamic = (firstArg is KtStringTemplateExpression && firstArg.hasInterpolation()) ||
            firstArg.isDynamicStringConcat()
        if (dynamic) {
            reportAt(
                expression,
                "XPath $callee() with dynamic expression — use XPathVariableResolver to bind variables safely",
            )
        }
    }
}
