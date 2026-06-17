package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A01 — Broken Access Control
 * CVE-2023-6267: Quarkus reads the JSON body before enforcing method-level security,
 * allowing unauthenticated callers to trigger deserialization. Fix: move @RolesAllowed to the class.
 */
class QuarkusJsonBeforeAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusJsonBeforeAuth",
        severity = Severity.Security,
        description = "CVE-2023-6267: method-level-only security on @Path class — JSON parsed before auth",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        val classAnnotations = klass.annotationNames()
        if ("Path" !in classAnnotations) return
        if (DetectionPatterns.QUARKUS_AUTH_ANNOTATIONS.any { it in classAnnotations }) return
        val methods = klass.declarations.filterIsInstance<KtNamedFunction>()
        val hasMethodSecurity = methods.any { fn ->
            DetectionPatterns.QUARKUS_AUTH_ANNOTATIONS.any { it in fn.annotationNames() }
        }
        if (!hasMethodSecurity) return
        reportAt(
            klass,
            "CVE-2023-6267: @Path class without class-level security — annotate the class with @RolesAllowed",
        )
    }
}
