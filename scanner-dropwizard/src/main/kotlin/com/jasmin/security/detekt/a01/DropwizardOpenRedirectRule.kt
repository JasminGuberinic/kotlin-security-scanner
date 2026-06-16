package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (Open Redirect)
 * FindSecBugs: UNVALIDATED_REDIRECT
 *
 * Flags JAX-RS Response.seeOther()/temporaryRedirect() calls where the target URI
 * is constructed from dynamic input. An attacker can supply an external URL to redirect
 * victims to a phishing site while the origin appears trustworthy.
 *
 * Compliant:
 *   Response.seeOther(URI("/dashboard")).build()        // literal path — safe
 *
 * Non-compliant:
 *   Response.seeOther(URI(userInput)).build()           // variable — attacker-controlled
 *   Response.seeOther(URI("https://${'$'}host/login")).build() // interpolated
 */
class DropwizardOpenRedirectRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardOpenRedirect",
        severity = Severity.Security,
        description = "JAX-RS redirect target from non-literal input — validate against an allowlist",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.JAXRS_REDIRECT_METHODS) return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (isNonLiteralTarget(arg)) {
            reportAt(
                expression,
                "Response.$callee() with dynamic URI — validate against an allowlist to prevent open redirect",
            )
        }
    }

    @Suppress("ReturnCount")
    private fun isNonLiteralTarget(arg: KtExpression): Boolean {
        if (arg is KtCallExpression) {
            val argCallee = arg.calleeExpression?.text ?: return false
            if (argCallee !in DetectionPatterns.SSRF_CONSTRUCTORS) return false
            val uriArg = arg.valueArguments.firstOrNull()?.getArgumentExpression() ?: return true
            if (uriArg !is KtStringTemplateExpression) return true
            return uriArg.hasInterpolation()
        }
        return arg !is KtStringTemplateExpression
    }
}
