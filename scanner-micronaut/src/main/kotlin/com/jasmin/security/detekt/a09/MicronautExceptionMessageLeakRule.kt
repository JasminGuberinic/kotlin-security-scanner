package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType
import org.jetbrains.kotlin.psi.psiUtil.getParentOfType

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

    private val messageSelectors = setOf("message", "localizedMessage")
    private val logMethods = setOf("error", "warn", "debug", "info", "trace")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if ("Error" !in function.annotationNames()) return
        val body = function.bodyExpression ?: function.bodyBlockExpression ?: return

        // Find every `<expr>.message` / `<expr>.localizedMessage` access in the body.
        // A handler leaks only if at least one such access is NOT confined to a
        // server-side logging call. We inspect PSI structure rather than string-
        // stripping so nested parentheses (e.g. logger.error("ctx=" + ctx(), e.message))
        // are handled correctly.
        val leaks = body.collectDescendantsOfType<KtDotQualifiedExpression> { dotted ->
            dotted.selectorExpression?.text in messageSelectors
        }
        if (leaks.isEmpty()) return

        val leaksOutsideLogging = leaks.any { !it.isInsideLoggingCall() }
        if (!leaksOutsideLogging) return

        reportAt(
            function,
            "@Error handler leaks exception.message — log the cause server-side and return a generic response",
        )
    }

    /** True when this `.message` access is an argument to a `log*.error(...)`-style call. */
    private fun KtDotQualifiedExpression.isInsideLoggingCall(): Boolean {
        var enclosing = getParentOfType<KtCallExpression>(strict = true)
        while (enclosing != null) {
            if (enclosing.isLoggingCall()) return true
            enclosing = enclosing.getParentOfType<KtCallExpression>(strict = true)
        }
        return false
    }

    /** True for receiver.method(...) where receiver looks like a logger and method is a log level. */
    private fun KtCallExpression.isLoggingCall(): Boolean {
        val method = calleeExpression?.text ?: return false
        if (method !in logMethods) return false
        val receiver = (parent as? KtDotQualifiedExpression)
            ?.receiverExpression?.text
            ?.substringAfterLast(".")
            ?: return false
        return receiver.lowercase().startsWith("log")
    }
}
