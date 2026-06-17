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
        val body = function.bodyExpression?.text ?: return
        val found = DetectionPatterns.EXCEPTION_DETAIL_PATTERNS.any { it in body }
        if (!found) return
        reportAt(
            function,
            "@ExceptionHandler exposes exception details to the client — return a generic error response",
        )
    }
}
