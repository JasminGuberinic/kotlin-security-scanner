package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A09 — Security Logging and Monitoring Failures (CWE-209)
// An @Error handler that returns exception.message leaks internal stack paths,
// database names, and class names to the client — valuable reconnaissance for attackers.
// Compliant:   HttpResponse.serverError("Internal error")  (log the real cause server-side)
// Non-compliant: HttpResponse.serverError(e.message)
class MicronautExceptionMessageLeakRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautExceptionMessageLeak",
        severity = Severity.Security,
        description = "@Error handler exposes exception.message to the client — return a generic error message",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if ("Error" !in function.annotationNames()) return
        val body = function.bodyExpression?.text ?: function.bodyBlockExpression?.text ?: return
        if (".message" !in body && ".localizedMessage" !in body) return
        // Allow if it only appears in a log call (logger.error(...message...))
        if (body.contains(Regex("""log\w*\.(error|warn|debug|info|trace)\s*\("""))) {
            val nonLogBody = body.replace(Regex("""log\w*\.\w+\s*\([^)]*\)"""), "")
            if (".message" !in nonLogBody && ".localizedMessage" !in nonLogBody) return
        }
        reportAt(function, "@Error handler leaks exception.message — log the cause server-side and return a generic response")
    }
}
