package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A01 — Broken Access Control
// A JAX-RS @POST endpoint that accepts form data (APPLICATION_FORM_URLENCODED) without
// checking a CSRF token is vulnerable to cross-site request forgery.
// Compliant:   check @HeaderParam("X-CSRF-Token") or use @CSRF Quarkus extension
// Non-compliant: @POST @Consumes(MediaType.APPLICATION_FORM_URLENCODED) without CSRF check
class QuarkusFormCsrfMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusFormCsrfMissing",
        severity = Severity.Security,
        description = "JAX-RS form endpoint without CSRF protection — cross-site request forgery risk",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationEntries.mapNotNull { it.shortName?.asString() }
        if ("POST" !in annotations && "PUT" !in annotations) return
        val consumesAnnotation = function.annotationEntries
            .find { it.shortName?.asString() == "Consumes" } ?: return
        val consumesText = consumesAnnotation.text
        if ("APPLICATION_FORM_URLENCODED" !in consumesText && "MULTIPART_FORM_DATA" !in consumesText) return
        // if function has X-CSRF-Token header param, it's protected
        val hasCsrfParam = function.valueParameters.any { param ->
            val headerParam = param.annotationEntries.find { it.shortName?.asString() == "HeaderParam" }
            val headerName = headerParam?.valueArguments?.firstOrNull()?.getArgumentExpression()?.text ?: ""
            "csrf" in headerName.lowercase() || "xsrf" in headerName.lowercase()
        }
        if (hasCsrfParam) return
        reportAt(
            function,
            "Form endpoint without CSRF token check — " +
                "add @HeaderParam(\"X-CSRF-Token\") or use the Quarkus CSRF extension",
        )
    }
}
