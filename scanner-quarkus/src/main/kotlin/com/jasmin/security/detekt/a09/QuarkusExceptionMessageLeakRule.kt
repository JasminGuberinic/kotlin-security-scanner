package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A09 — Security Logging and Monitoring Failures
// Returning exception.message in the HTTP response reveals internal class names,
// SQL queries, and file paths — aids reconnaissance attacks.
// Compliant:   Response.serverError().entity("Internal error").build()
// Non-compliant: Response.serverError().entity(e.message).build()
class QuarkusExceptionMessageLeakRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusExceptionMessageLeak",
        severity = Severity.Security,
        description = "Exception message returned in JAX-RS Response — exposes internal details to callers",
        debt = Debt.TWENTY_MINS,
    )

    private val exceptionLeakPatterns = listOf(
        Regex("""ex\.(message|localizedMessage|stackTraceToString|toString)\b"""),
        Regex("""e\.(message|localizedMessage|stackTraceToString|toString)\b"""),
        Regex("""exception\.(message|localizedMessage|stackTraceToString|toString)\b"""),
        Regex("""it\.(message|localizedMessage|stackTraceToString|toString)\b"""),
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val isExceptionMapper = function.annotationEntries.any {
            it.shortName?.asString() in setOf("ExceptionMapper", "ServerExceptionMapper", "Provider")
        }
        if (!isExceptionMapper) return
        val bodyText = function.bodyExpression?.text ?: return
        if (exceptionLeakPatterns.none { it.containsMatchIn(bodyText) }) return
        reportAt(
            function,
            "Exception mapper returning exception details — use a generic error message",
        )
    }
}
