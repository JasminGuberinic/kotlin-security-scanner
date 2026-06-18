package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A03 — Injection
// @PathParam parameters injected directly into a Panache/JPQL query string enable injection.
// Compliant:   Entity.find("name = ?1", name)  // positional param binding
// Non-compliant: Entity.find("name = '$name'")  // string template injection
@Suppress("ReturnCount")
class QuarkusPathParamInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusPathParamInjection",
        severity = Severity.Security,
        description = "@PathParam value interpolated into Panache query — use positional parameters",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val hasPathParam = function.valueParameters.any { param ->
            param.annotationEntries.any { it.shortName?.asString() == "PathParam" }
        }
        if (!hasPathParam) return
        val body = function.bodyExpression?.text ?: return
        val panacheMethods = setOf("find", "list", "stream", "count", "delete", "update")
        val hasDangerousQuery = panacheMethods.any { method ->
            Regex("""$method\s*\(\s*"[^"]*\$""").containsMatchIn(body)
        }
        if (!hasDangerousQuery) return
        reportAt(
            function,
            "@PathParam value in Panache query — use positional params: find(\"name = ?1\", name)",
        )
    }
}
