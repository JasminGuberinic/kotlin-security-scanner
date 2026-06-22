package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtLambdaExpression

// OWASP A09 — Security Logging and Monitoring Failures (CWE-209)
// exception<Exception> { cause -> call.respond(cause.message) } leaks internal
// stack traces, class names, and error details to the client. Attackers use this
// to map the application and discover exploitable paths.
// Compliant:   exception<Exception> { _ -> call.respond(HttpStatusCode.InternalServerError, "Internal error") }
// Non-compliant: exception<Exception> { cause -> call.respond(cause.message) }
class KtorStatusPageLeakDetailsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorStatusPageLeakDetails",
        severity = Severity.Security,
        description = "exception<Exception> handler exposes cause details in HTTP response — return a generic error message",
        debt = Debt.TWENTY_MINS,
    )

    private val leakIndicators = listOf("cause.message", "cause.toString()", "it.message", "it.toString()", "stackTrace", ".localizedMessage")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "exception") return
        val lambda = expression.lambdaArguments.firstOrNull()
            ?.getLambdaExpression()
            ?: (expression.valueArguments.lastOrNull()?.getArgumentExpression() as? KtLambdaExpression)
            ?: return
        val lambdaText = lambda.text
        val hasRespondCall = "call.respond" in lambdaText || "call.respondText" in lambdaText
        if (!hasRespondCall) return
        val leaksDetails = leakIndicators.any { it in lambdaText }
        if (!leaksDetails) return
        reportAt(
            expression,
            "exception handler responds with cause.message — return a generic error code instead",
        )
    }
}
