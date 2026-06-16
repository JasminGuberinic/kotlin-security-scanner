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
 * OWASP A03 — Injection (JNDI)
 * FindSecBugs: JNDI_INJECTION
 *
 * Flags JNDI lookup/rebind calls where the name argument is not a string literal.
 * An attacker who controls the JNDI name can supply a remote URL (ldap://, rmi://)
 * that causes the JVM to load and execute an attacker-hosted class — remote code
 * execution (Log4Shell-class vulnerability).
 *
 * Compliant:
 *   ctx.lookup("java:comp/env/jdbc/MyDs")    // literal — safe
 *
 * Non-compliant:
 *   ctx.lookup(name)                          // variable — may be a remote URL
 *   ctx.lookup("ldap://${'$'}host/exploit")  // interpolated — attacker-controlled host
 */
class JndiInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "JndiInjection",
        severity = Severity.Security,
        description = "JNDI lookup with non-literal name — dynamic names can be remote URLs (RCE risk)",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.JNDI_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (!isSafe) {
            reportAt(
                expression,
                "JNDI $callee() with dynamic name — use a hardcoded allowlist of permitted JNDI names",
            )
        }
    }
}
