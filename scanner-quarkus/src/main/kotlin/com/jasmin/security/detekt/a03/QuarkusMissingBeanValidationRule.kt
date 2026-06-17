package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A03 — Injection
 * JAX-RS @POST/@PUT methods that accept an entity body without @Valid skip Bean Validation,
 * allowing malformed or malicious payloads to reach business logic unchecked.
 */
class QuarkusMissingBeanValidationRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusMissingBeanValidation",
        severity = Severity.Security,
        description = "JAX-RS entity parameter missing @Valid — input not validated",
        debt = Debt.TEN_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        if (DetectionPatterns.JAXRS_ENTITY_METHODS.none { it in annotations }) return
        function.valueParameters.forEach { param ->
            val paramAnnotations = param.annotationNames()
            if (DetectionPatterns.JAXRS_PARAM_ANNOTATIONS.any { it in paramAnnotations }) return@forEach
            if ("Valid" in paramAnnotations) return@forEach
            reportAt(
                param,
                "JAX-RS entity parameter '${param.name}' lacks @Valid — add @Valid to enforce Bean Validation",
            )
        }
    }
}
