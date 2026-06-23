package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A05 — Security Misconfiguration (Permissive CORS / CWE-942)
 *
 * anyHeader() in the CORS plugin allows requests carrying any header, including custom
 * authentication headers, from cross-origin callers. Combined with credentialed
 * requests this widens the cross-origin attack surface. Allow only the specific
 * headers your API needs.
 *
 * Non-compliant:
 *   install(CORS) { anyHeader() }
 */
class KtorCorsAnyHeaderRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorCorsAnyHeader",
        severity = Severity.Security,
        description = "CORS anyHeader() accepts any cross-origin request header — allow only the headers you need",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "anyHeader") return
        reportAt(expression, "CORS anyHeader() is overly permissive — call allowHeader(...) for each required header")
    }
}
