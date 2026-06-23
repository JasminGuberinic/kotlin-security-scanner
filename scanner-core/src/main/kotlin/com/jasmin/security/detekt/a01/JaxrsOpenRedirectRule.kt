package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (Open Redirect)
 * FindSecBugs: UNVALIDATED_REDIRECT
 *
 * Flags JAX-RS / Micronaut Response.seeOther() / temporaryRedirect() calls where the
 * target URI is constructed from dynamic input. An attacker can supply an external URL
 * to redirect victims to a phishing site while the origin appears trustworthy.
 *
 * Applies to: Quarkus, Dropwizard, Micronaut — any code using the JAX-RS Response API
 * or Micronaut HttpResponse with dynamic URI construction.
 *
 * Compliant:
 *   Response.seeOther(URI("/dashboard")).build()        // literal path — safe
 *
 * Non-compliant:
 *   Response.seeOther(URI(userInput)).build()           // variable — attacker-controlled
 *   HttpResponse.seeOther(URI(url))                     // Micronaut
 */
class JaxrsOpenRedirectRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "JaxrsOpenRedirect",
        severity = Severity.Security,
        description = "JAX-RS/Micronaut redirect target from non-literal input — validate against an allowlist",
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
        // The target may be a constructor call `URI("...")` (a KtCallExpression) or a factory
        // call `URI.create("...")` (a KtDotQualifiedExpression whose selector is the call —
        // its callee text is just "create", so the URI/URL class is the dot-qualified receiver).
        val call = arg as? KtCallExpression
            ?: (arg as? KtDotQualifiedExpression)?.selectorExpression as? KtCallExpression
        if (call != null) {
            val argSimple = call.calleeExpression?.text?.substringAfterLast(".") ?: return true
            val isConstructor = argSimple in DetectionPatterns.SSRF_CONSTRUCTORS
            val isCreateFactory = argSimple == "create" &&
                (arg as? KtDotQualifiedExpression)?.receiverExpression?.text
                    ?.substringAfterLast(".") in DetectionPatterns.SSRF_CONSTRUCTORS
            if (isConstructor || isCreateFactory) {
                val uriArg = call.valueArguments.firstOrNull()?.getArgumentExpression() ?: return true
                return uriArg !is KtStringTemplateExpression || uriArg.hasInterpolation()
            }
            // Some other call produces the target (e.g. a helper) — treat as dynamic.
            return true
        }
        // A bare string literal is safe; a variable or any other expression is dynamic.
        return arg !is KtStringTemplateExpression
    }
}
