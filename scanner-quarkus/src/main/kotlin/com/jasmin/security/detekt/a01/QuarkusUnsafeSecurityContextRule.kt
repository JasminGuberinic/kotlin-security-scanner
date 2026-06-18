package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A01 — Broken Access Control
// Injecting SecurityContext via @Context but not calling isUserInRole() or
// getUserPrincipal() means the context is unused for authorization, which is
// typically a missing access control check.
// Compliant:   if (!ctx.isUserInRole("admin")) throw ForbiddenException()
// Non-compliant: fun sensitive(@Context ctx: SecurityContext) { ... /* no role check */ }
class QuarkusUnsafeSecurityContextRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusUnsafeSecurityContext",
        severity = Severity.Security,
        description = "@Context SecurityContext injected but isUserInRole/getPrincipal not called",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val hasSecurityContextParam = function.valueParameters.any { param ->
            val hasContextAnnotation = param.annotationEntries
                .any { it.shortName?.asString() == "Context" }
            val paramType = param.typeReference?.text ?: ""
            hasContextAnnotation && "SecurityContext" in paramType
        }
        if (!hasSecurityContextParam) return
        val bodyText = function.bodyExpression?.text ?: return
        if ("isUserInRole" in bodyText || "userPrincipal" in bodyText || "getUserPrincipal" in bodyText) return
        reportAt(
            function,
            "@Context SecurityContext injected but never used for role/principal check — add isUserInRole() check",
        )
    }
}
