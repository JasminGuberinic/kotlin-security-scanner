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
 * OWASP A03 — Injection (LDAP)
 * FindSecBugs: LDAP_INJECTION
 *
 * Flags LDAP operations (search, bind, lookup) where a string argument
 * contains interpolation. LDAP special characters in user input can alter
 * the filter logic, enabling authentication bypass and data exfiltration.
 *
 * Compliant:
 *   val filter = "(uid={0})"
 *   ctx.search("ou=users", filter, SearchControls())   // parameterised
 *
 * Non-compliant:
 *   val filter = "(uid=${'$'}username)"
 *   ctx.search("ou=users", filter, SearchControls())   // interpolated
 */
class LdapInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "LdapInjection",
        severity = Severity.Security,
        description = "LDAP operation with interpolated argument — escape input or use parameterised filters",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.LDAP_OPERATION_METHODS) return
        if (hasInterpolatedStringArg(expression)) {
            reportAt(
                expression,
                "LDAP $callee() uses an interpolated filter — escape user input with LdapEncoder.filterEncode()",
            )
        }
    }

    private fun hasInterpolatedStringArg(expression: KtCallExpression) =
        expression.valueArguments.any { arg ->
            val e = arg.getArgumentExpression() as? KtStringTemplateExpression ?: return@any false
            e.hasInterpolation()
        }
}
