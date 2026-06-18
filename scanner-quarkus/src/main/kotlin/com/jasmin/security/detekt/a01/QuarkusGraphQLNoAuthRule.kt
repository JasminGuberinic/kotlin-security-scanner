package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass

// OWASP A01 — Broken Access Control
// @GraphQLApi classes expose all @Query and @Mutation methods via GraphQL.
// Without class-level @RolesAllowed or @Authenticated, every operation is public.
// Compliant:   @GraphQLApi @RolesAllowed("user") class ProductApi
// Non-compliant: @GraphQLApi class ProductApi  // all queries publicly accessible
class QuarkusGraphQLNoAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusGraphQLNoAuth",
        severity = Severity.Security,
        description = "@GraphQLApi class missing access-control annotation — all operations are public",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        val annotations = klass.annotationEntries.map { it.shortName?.asString() ?: "" }.toSet()
        if ("GraphQLApi" !in annotations) return
        if (annotations.any { it in DetectionPatterns.QUARKUS_AUTH_ANNOTATIONS }) return
        reportAt(klass, "@GraphQLApi without @RolesAllowed or @Authenticated — add class-level access control")
    }
}
