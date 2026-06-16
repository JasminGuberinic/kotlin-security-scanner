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
 * Flags Quarkus JAX-RS resource methods that combine @PermitAll with
 * state-changing HTTP methods (@DELETE, @PUT, @PATCH). @PermitAll on a
 * write operation means any unauthenticated caller can modify or delete
 * resources — almost always a design mistake.
 *
 * Compliant:
 *   @GET @PermitAll fun health(): Response       // read-only public endpoint
 *   @DELETE @RolesAllowed("admin") fun delete()  // protected write operation
 *
 * Non-compliant:
 *   @DELETE @PermitAll fun deleteUser()           // anonymous deletion
 *   @PUT @PermitAll fun updateConfig()            // anonymous update
 */
class QuarkusPermitAllSensitiveRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusPermitAllSensitive",
        severity = Severity.Security,
        description = "@PermitAll on a write operation allows unauthenticated callers to mutate data",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        if ("PermitAll" !in annotations) return
        val writeMethod = annotations.firstOrNull { it in DetectionPatterns.JAXRS_WRITE_METHODS } ?: return
        reportAt(
            function,
            "@$writeMethod combined with @PermitAll allows anonymous writes — add @RolesAllowed or @Authenticated",
        )
    }
}
