package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A03 — Injection (Cross-Site Scripting)
// @Produces(MediaType.TEXT_HTML) on a JAX-RS method outputs raw HTML.
// Without output encoding, user-supplied values become XSS injection points.
// Compliant:   @Produces(MediaType.APPLICATION_JSON) — or encode HTML entities before output
// Non-compliant: @Produces("text/html") fun page(@QueryParam("name") name: String) = "<h1>$name</h1>"
class DropwizardXssResponseRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardXssResponse",
        severity = Severity.Security,
        description = "@Produces(text/html) JAX-RS method — output must be HTML-encoded to prevent XSS",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationEntries
        val hasTextHtml = annotations.any { ann ->
            val text = ann.text
            "Produces" in text && ("text/html" in text || "TEXT_HTML" in text)
        }
        if (!hasTextHtml) return
        reportAt(function, "@Produces(text/html) — HTML-encode all user-supplied values before output")
    }
}
