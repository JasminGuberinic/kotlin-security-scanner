package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A01 — Broken Access Control
// Quarkus Reactive Routes (@Route) bypass the JAX-RS filter chain.
// Without @Authenticated or @RolesAllowed the route has no access control.
// Compliant:   @Route(path="/profile") @Authenticated fun profile(rc: RoutingContext)
// Non-compliant: @Route(path="/profile") fun profile(rc: RoutingContext)
@Suppress("ReturnCount")
class QuarkusReactiveRouteNoAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusReactiveRouteNoAuth",
        severity = Severity.Security,
        description = "@Route method missing access-control annotation — reactive routes bypass JAX-RS filters",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        if ("Route" !in annotations) return
        if (annotations.any { it in DetectionPatterns.QUARKUS_AUTH_ANNOTATIONS }) return
        if ("PermitAll" in annotations || "DenyAll" in annotations) return
        reportAt(function, "@Route without @Authenticated or @RolesAllowed — add access control for reactive routes")
    }
}
