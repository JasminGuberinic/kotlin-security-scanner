package com.jasmin.security.detekt.a04

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtParameter

// OWASP A04 — Insecure Design
// @Body body: Any deserializes arbitrary JSON without schema enforcement, enabling
// mass assignment and polymorphic deserialization gadget attacks.
// Compliant:   @Body body: CreateUserRequest  (concrete DTO with validation)
// Non-compliant: @Body body: Any
class MicronautBodyAnyTypeRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautBodyAnyType",
        severity = Severity.Security,
        description = "@Body typed as Any bypasses schema validation — use a concrete DTO",
        debt = Debt.TWENTY_MINS,
    )

    private val unsafeTypes = setOf("Any", "Object", "Map", "MutableMap", "HashMap")

    @Suppress("ReturnCount")
    override fun visitParameter(parameter: KtParameter) {
        super.visitParameter(parameter)
        if ("Body" !in parameter.annotationNames()) return
        val typeText = parameter.typeReference?.text ?: return
        // Strip generic args, a trailing nullable marker, and any package qualifier:
        //   kotlin.Any?            -> Any
        //   MutableMap<String, Any>? -> MutableMap
        val baseType = typeText
            .substringBefore("<")
            .trim()
            .removeSuffix("?")
            .trim()
            .substringAfterLast(".")
        if (baseType !in unsafeTypes) return
        reportAt(
            parameter,
            "@Body typed as $baseType — define a concrete data class with @field:NotNull/@field:Size constraints",
        )
    }
}
