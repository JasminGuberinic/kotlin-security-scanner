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
 *
 * @CacheResult keys on method arguments only, ignoring the caller's identity. On a
 * method also guarded by @RolesAllowed / @Authenticated, the first user's result is
 * served to every other user who calls with the same arguments — a cross-user data
 * leak. Include the principal in the cache key or do not cache per-user data.
 *
 * Non-compliant:
 *   @CacheResult(cacheName = "profile") @RolesAllowed("user")
 *   fun profile(id: Long): Profile
 */
class QuarkusCacheResultSensitiveRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusCacheResultSensitive",
        severity = Severity.Security,
        description = "@CacheResult on a secured method caches per-user data across users",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        if ("CacheResult" !in annotations) return
        if (annotations.none { it in DetectionPatterns.QUARKUS_AUTH_ANNOTATIONS }) return
        reportAt(
            function,
            "@CacheResult on a secured method '${function.name}' leaks one user's result to others — " +
                "add the principal to the cache key",
        )
    }
}
