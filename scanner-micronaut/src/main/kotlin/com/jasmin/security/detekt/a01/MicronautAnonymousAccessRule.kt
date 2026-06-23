package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A01 — Broken Access Control
 *
 * @Secured(SecurityRule.IS_ANONYMOUS) (or @Secured("isAnonymous()")) on a
 * state-changing endpoint (@Post / @Put / @Delete / @Patch) exposes a write operation
 * to unauthenticated callers. Anonymous access belongs only on read-only public routes
 * such as login or health.
 *
 * Non-compliant:
 *   @Post @Secured(SecurityRule.IS_ANONYMOUS) fun delete(id: Long)
 */
class MicronautAnonymousAccessRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautAnonymousAccess",
        severity = Severity.Security,
        description = "Anonymous @Secured on a state-changing endpoint — unauthenticated callers can write",
        debt = Debt.TWENTY_MINS,
    )

    private val writeMethods = setOf("Post", "Put", "Delete", "Patch")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        val writeMethod = annotations.firstOrNull { it in writeMethods } ?: return
        val anonymous = function.annotationEntries.any { entry ->
            entry.shortName?.asString() == "Secured" && entry.text.contains("anonymous", ignoreCase = true)
        }
        if (anonymous) {
            reportAt(
                function,
                "@$writeMethod with @Secured anonymous — restrict write endpoints to authenticated roles",
            )
        }
    }
}
