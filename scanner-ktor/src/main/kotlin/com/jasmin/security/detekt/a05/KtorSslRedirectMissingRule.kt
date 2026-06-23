package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// A Ktor application that has routing configured without an HttpsRedirect plugin
// will accept plain HTTP requests and silently serve content over cleartext.
// Compliant:   install(HttpsRedirect) { sslPort = 443; permanentRedirect = true }
// Non-compliant: routing { get("/") { ... } } without install(HttpsRedirect)
class KtorSslRedirectMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorSslRedirectMissing",
        severity = Severity.Security,
        description = "Ktor app has routing without HttpsRedirect — HTTP requests served in cleartext",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.KTOR_ROUTING) return
        val parent = expression.parent ?: return
        val fileText = parent.containingFile?.text ?: return
        if ("HttpsRedirect" in fileText || "httpsRedirect" in fileText) return
        // Only fire when the SAME file sets up the application/server with other
        // plugins (an install(...) call) but no HttpsRedirect. A file that only
        // declares routes (plain Routing.kt) must NOT trigger — plugins are
        // commonly installed in a separate file.
        if (!Regex("""\binstall\s*\(""").containsMatchIn(fileText)) return
        reportAt(
            expression,
            "Ktor routing without HttpsRedirect — install(HttpsRedirect) to enforce TLS",
        )
    }
}
