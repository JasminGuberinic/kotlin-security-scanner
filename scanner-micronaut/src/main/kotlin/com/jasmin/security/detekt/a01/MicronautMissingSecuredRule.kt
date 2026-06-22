package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotated
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A01 — Broken Access Control
// Micronaut controller methods annotated with @Get / @Post / @Put / @Delete / @Patch
// that have no @Secured annotation at the method or class level are publicly accessible.
// Compliant:   @Get @Secured(SecurityRule.IS_AUTHENTICATED) fun list(): List<User>
//              OR @Secured(...) at class level protects all methods
// Non-compliant: @Get fun list(): List<User>   // unannotated = world-readable
class MicronautMissingSecuredRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautMissingSecured",
        severity = Severity.Security,
        description = "Micronaut controller endpoint lacks @Secured — all callers can access it",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val funcAnnotations = function.annotationNames()
        if (funcAnnotations.none { it in DetectionPatterns.MICRONAUT_HTTP_METHODS }) return

        val classAnnotations =
            (function.parent?.parent as? KtAnnotated)?.annotationNames() ?: emptySet()

        if (funcAnnotations.any { it in DetectionPatterns.MICRONAUT_AUTH_ANNOTATIONS }) return
        if (classAnnotations.any { it in DetectionPatterns.MICRONAUT_AUTH_ANNOTATIONS }) return

        val method = funcAnnotations.first { it in DetectionPatterns.MICRONAUT_HTTP_METHODS }
        reportAt(
            function,
            "@$method endpoint is missing @Secured — add @Secured(SecurityRule.IS_AUTHENTICATED) " +
                "or @Secured(SecurityRule.IS_ANONYMOUS) to make the intent explicit",
        )
    }
}
