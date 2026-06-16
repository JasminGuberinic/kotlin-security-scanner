package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A01 — Broken Access Control
 * FindSecBugs: JAXRS_ENDPOINT
 *
 * Flags JAX-RS resource methods annotated with @GET / @POST etc.
 * that are missing @RolesAllowed, @DenyAll on the method, or
 * @Auth on any parameter (Dropwizard's per-parameter principal injection).
 *
 * Compliant:
 *   @GET @RolesAllowed("ADMIN") fun list(): Response
 *   @POST fun create(@Auth user: User, dto: UserDto): Response
 *
 * Non-compliant:
 *   @GET fun list(): Response   // unprotected endpoint
 */
class DropwizardMissingAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardMissingAuth",
        severity = Severity.Security,
        description = "JAX-RS endpoint lacks access-control annotation",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)

        val methodAnnotations = function.annotationNames()
        if (hasHttpMethod(methodAnnotations) && lacksAuthGuard(function, methodAnnotations)) {
            reportAt(function, buildMessage(methodAnnotations))
        }
    }

    private fun hasHttpMethod(annotations: Set<String>) =
        annotations.any { it in DetectionPatterns.JAXRS_HTTP_METHODS }

    private fun lacksAuthGuard(function: KtNamedFunction, methodAnnotations: Set<String>): Boolean {
        if (methodAnnotations.any { it in DetectionPatterns.JAXRS_AUTH_ANNOTATIONS }) return false
        // @Auth is a parameter-level annotation in Dropwizard
        return function.valueParameters.none { param ->
            param.annotationEntries
                .mapNotNull { it.shortName?.asString() }
                .any { it == "Auth" }
        }
    }

    private fun buildMessage(annotations: Set<String>): String {
        val method = annotations.first { it in DetectionPatterns.JAXRS_HTTP_METHODS }
        return "@$method endpoint is missing @RolesAllowed, @DenyAll, or @Auth — " +
            "unauthenticated callers may access this resource"
    }
}
