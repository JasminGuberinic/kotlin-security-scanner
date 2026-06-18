package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A09 — Security Logging and Monitoring Failures
// Returning exception.message or stack traces in HTTP response bodies reveals internal
// implementation details (class names, SQL, file paths) that aid attackers.
// Compliant:   return ResponseEntity.status(500).body(mapOf("error" to "Internal error"))
// Non-compliant: return ResponseEntity.badRequest().body(ex.message)
class SpringBootExceptionBodyLeakRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringBootExceptionBodyLeak",
        severity = Severity.Security,
        description = "Exception details returned in HTTP response — may expose internals to clients",
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
        val hasExceptionHandler = function.annotationEntries.any {
            it.shortName?.asString() == "ExceptionHandler"
        }
        if (!hasExceptionHandler) return
        val bodyText = function.bodyExpression?.text ?: return
        if (exceptionLeakPatterns.none { it.containsMatchIn(bodyText) }) return
        reportAt(
            function,
            "@ExceptionHandler returning exception details — return a generic error message instead",
        )
    }
}
