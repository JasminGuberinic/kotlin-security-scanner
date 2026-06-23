package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A01 — Broken Access Control (CSRF)
// A state-changing Ktor route (POST/PUT/DELETE/PATCH) without reading the CSRF
// header or Origin is vulnerable to cross-site request forgery.
// Compliant:   post("/transfer") { val csrf = call.request.header("X-CSRF-Token"); require(csrf != null) }
// Non-compliant: post("/transfer") { val body = call.receive<TransferRequest>(); process(body) }
class KtorCsrfMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorCsrfMissing",
        severity = Severity.Security,
        description = "Ktor state-changing route without CSRF token check — validate X-CSRF-Token header",
        debt = Debt.TWENTY_MINS,
    )

    private val mutatingMethods = setOf("post", "put", "delete", "patch")
    private val csrfIndicators = setOf("X-CSRF-Token", "csrfToken", "csrf", "Origin", "Referer")

    private val routeBuilders = setOf("routing", "route")
    private val authGuards = setOf("authenticate", "authorize")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in mutatingMethods) return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: return
        // Route definitions take a string-literal path as the first argument.
        // This excludes the Ktor HTTP CLIENT (client.post(url) { }) and unrelated DSLs.
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()
        val hasLiteralPath = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (!hasLiteralPath) return
        // Only treat as a route when nested inside a routing/route builder.
        if (!hasRouteAncestor(expression)) return
        if (csrfIndicators.any { it in lambdaText }) return
        // A route guarded by authenticate {}/authorize {} anywhere up the tree is protected.
        if (hasAuthAncestor(expression)) return
        reportAt(expression, "$callee() route without CSRF token check — validate X-CSRF-Token or use SameSite=Strict")
    }

    private fun hasRouteAncestor(expression: KtCallExpression): Boolean =
        hasAncestorCall(expression, routeBuilders)

    private fun hasAuthAncestor(expression: KtCallExpression): Boolean =
        hasAncestorCall(expression, authGuards)

    private fun hasAncestorCall(expression: KtCallExpression, callees: Set<String>): Boolean {
        var current = expression.parent
        while (current != null) {
            if (current is KtCallExpression && current.calleeExpression?.text in callees) return true
            current = current.parent
        }
        return false
    }
}
