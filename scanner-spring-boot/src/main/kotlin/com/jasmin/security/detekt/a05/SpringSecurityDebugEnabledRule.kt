package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass

/**
 * OWASP A05 — Security Misconfiguration
 *
 * @EnableWebSecurity(debug = true) prints every incoming request, matched
 * filter chain, and security decision to the log. In production this leaks
 * authentication details, session tokens, and internal routing.
 *
 * Compliant:
 *   @EnableWebSecurity
 *   class SecurityConfig : WebSecurityConfigurerAdapter()
 *
 * Non-compliant:
 *   @EnableWebSecurity(debug = true)
 *   class SecurityConfig : WebSecurityConfigurerAdapter()
 */
class SpringSecurityDebugEnabledRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringSecurityDebugEnabled",
        severity = Severity.Security,
        description = "@EnableWebSecurity(debug=true) logs security internals — disable in production",
        debt = Debt.FIVE_MINS,
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        val annotation = klass.annotationEntries.find {
            it.shortName?.asString() == "EnableWebSecurity"
        } ?: return
        val hasDebugTrue = annotation.valueArguments.any { arg ->
            arg.getArgumentName()?.asName?.asString() == "debug" &&
                arg.getArgumentExpression()?.text == "true"
        }
        if (!hasDebugTrue) return
        reportAt(klass, "@EnableWebSecurity(debug=true) logs all requests and security decisions — remove in prod")
    }
}
