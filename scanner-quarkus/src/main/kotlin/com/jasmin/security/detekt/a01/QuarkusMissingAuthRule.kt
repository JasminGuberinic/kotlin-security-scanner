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
 * Flags JAX-RS resource methods (@GET / @POST etc.) in Quarkus applications
 * that have no access-control annotation.
 *
 * Quarkus supports both the standard JSR-250 annotations and its own
 * @Authenticated from io.quarkus.security, which requires any valid identity.
 *
 * Compliant:
 *   @GET @RolesAllowed("user") fun list(): Response
 *   @GET @Authenticated fun profile(): Response
 *   @GET @PermitAll fun health(): Response       // explicitly public
 *
 * Non-compliant:
 *   @GET fun list(): Response                    // unannotated = unprotected
 */
class QuarkusMissingAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusMissingAuth",
        severity = Severity.Security,
        description = "Quarkus JAX-RS endpoint lacks access-control annotation",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)

        val annotations = function.annotationNames()
        if (hasHttpMethod(annotations) && lacksAuthAnnotation(annotations)) {
            reportAt(function, buildMessage(annotations))
        }
    }

    private fun hasHttpMethod(annotations: Set<String>) =
        annotations.any { it in DetectionPatterns.JAXRS_HTTP_METHODS }

    private fun lacksAuthAnnotation(annotations: Set<String>) =
        annotations.none { it in DetectionPatterns.QUARKUS_AUTH_ANNOTATIONS }

    private fun buildMessage(annotations: Set<String>): String {
        val method = annotations.first { it in DetectionPatterns.JAXRS_HTTP_METHODS }
        return "@$method endpoint is missing @RolesAllowed, @Authenticated, @PermitAll, or @DenyAll — " +
            "add an explicit access-control annotation or Quarkus will allow all callers"
    }
}
