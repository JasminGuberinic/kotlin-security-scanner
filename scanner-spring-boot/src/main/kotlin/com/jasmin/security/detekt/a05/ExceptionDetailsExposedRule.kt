package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A05 — Security Misconfiguration
 *
 * An @ExceptionHandler that returns exception.message, localizedMessage,
 * stackTrace, or calls printStackTrace() leaks internal implementation details
 * — file paths, class names, library versions — to the client. Attackers use
 * this to fingerprint the stack and craft targeted exploits.
 *
 * Compliant:
 *   @ExceptionHandler fun handle(e: Exception) =
 *       ResponseEntity.internalServerError().body("An error occurred")
 *
 * Non-compliant:
 *   @ExceptionHandler fun handle(e: Exception) =
 *       ResponseEntity.badRequest().body(e.message)
 */
class ExceptionDetailsExposedRule(config: Config) : SecurityRule(config) {

    // Matches a logging call and its arguments, e.g. logger.error("..", e.message) or log.warn(e).
    // We strip these out so that an exception detail that is only LOGGED (not returned) is ignored.
    private val LOG_CALL = Regex("""\b(log|logger|LOG|LOGGER)\s*\.\s*\w+\s*\([^)]*\)""")

    override val issue = Issue(
        id = "ExceptionDetailsExposed",
        severity = Severity.Security,
        description = "@ExceptionHandler exposes internal exception details to the client",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if (DetectionPatterns.EXCEPTION_HANDLER_ANNOTATION !in function.annotationNames()) return
        val rawBody = function.bodyExpression?.text ?: return
        // Ignore exception details that only appear inside a logging call — those are not returned.
        val body = LOG_CALL.replace(rawBody, "")
        val found = DetectionPatterns.EXCEPTION_DETAIL_PATTERNS.any { it in body }
        if (!found) return
        reportAt(
            function,
            "@ExceptionHandler exposes exception details to the client — return a generic error response",
        )
    }
}
