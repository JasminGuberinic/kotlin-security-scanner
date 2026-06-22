package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A01 — Broken Access Control / A04 Insecure Design
// @Cacheable on a secured method risks returning a cached response for user A to user B
// when both make the same call. Unless the cache key includes the principal, the cache
// leaks user-specific data across authentication boundaries.
// Compliant:   @Cacheable("public-data") fun publicInfo() // no auth, safe to cache
// Non-compliant: @Cacheable("user-data") @Secured(...) fun userProfile() // user-specific
class MicronautCacheableSensitiveRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautCacheableSensitive",
        severity = Severity.Security,
        description = "@Cacheable on a secured method may serve cached responses across users — ensure cache key includes the principal",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val funcAnnotations = function.annotationNames()
        if ("Cacheable" !in funcAnnotations) return
        if ("Secured" in funcAnnotations) {
            reportAt(
                function,
                "@Cacheable + @Secured on '${function.name}' — the cache must include the authenticated principal in its key to avoid cross-user data leakage",
            )
            return
        }
        // Also flag if the enclosing class has @Secured at class level
        val enclosingClass = function.parent?.parent as? KtClass ?: return
        if ("Secured" in enclosingClass.annotationNames()) {
            reportAt(
                function,
                "@Cacheable on '${function.name}' inside a @Secured class — the cache must include the authenticated principal in its key",
            )
        }
    }
}
