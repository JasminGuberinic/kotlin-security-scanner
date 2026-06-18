package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A03 — Injection / A04 Insecure Design
// POST/PUT endpoints that accept a request body without @Valid bypass Bean Validation.
// Unvalidated input can contain SQL-injectable strings, oversized fields, or malformed data.
// Compliant:   fun create(@Valid @NotNull req: CreateUserRequest): Response
// Non-compliant: fun create(req: CreateUserRequest): Response
class DropwizardMissingBeanValidationRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardMissingBeanValidation",
        severity = Severity.Security,
        description = "JAX-RS POST/PUT parameter missing @Valid — request body not validated",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        val isWriteMethod = annotations.any { it in DetectionPatterns.JAXRS_ENTITY_METHODS }
        if (!isWriteMethod) return
        val params = function.valueParameters
        if (params.isEmpty()) return
        val bodyParam = params.firstOrNull { param ->
            param.annotationEntries.none { ann ->
                ann.shortName?.asString() in setOf(
                    "PathParam", "QueryParam", "HeaderParam", "CookieParam", "FormParam", "Context",
                )
            }
        } ?: return
        val hasValid = bodyParam.annotationEntries.any {
            it.shortName?.asString() in setOf("Valid", "NotNull", "NotEmpty", "NotBlank")
        }
        if (hasValid) return
        reportAt(function, "POST/PUT parameter '${bodyParam.name}' missing @Valid — add bean validation")
    }
}
