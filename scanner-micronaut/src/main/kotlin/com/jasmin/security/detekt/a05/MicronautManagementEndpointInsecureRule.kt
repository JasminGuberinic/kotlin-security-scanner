package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A05 — Security Misconfiguration
// Micronaut management endpoints (@Endpoint) expose operational data (metrics, health details,
// env dumps). Without @Secured on the class or each @Read/@Write method they are publicly
// accessible. Sensitive details should be protected behind authentication.
// Compliant:   @Endpoint("metrics") @Secured(SecurityRule.IS_AUTHENTICATED) class MetricsEndpoint
// Non-compliant: @Endpoint("metrics") class MetricsEndpoint { @Read fun details(): Map<...> }
class MicronautManagementEndpointInsecureRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautManagementEndpointInsecure",
        severity = Severity.Security,
        description = "@Endpoint management method without @Secured is publicly accessible",
        debt = Debt.TWENTY_MINS,
    )

    private val endpointOperations = setOf("Read", "Write", "Delete")

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        if ("Endpoint" !in klass.annotationNames()) return
        if ("Secured" in klass.annotationNames()) return
        klass.declarations
            .filterIsInstance<KtNamedFunction>()
            .filter { fn ->
                val fnAnnotations = fn.annotationNames()
                endpointOperations.any { it in fnAnnotations } && "Secured" !in fnAnnotations
            }
            .forEach { fn ->
                reportAt(
                    fn,
                    "@Endpoint operation '${fn.name}' has no @Secured — add @Secured(SecurityRule.IS_AUTHENTICATED) or secure at class level",
                )
            }
    }
}
