package com.jasmin.security.detekt.a04

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtParameter

/**
 * OWASP A04 — Insecure Design (Mass Assignment)
 * FindSecBugs: MASS_ASSIGNMENT
 *
 * Flags Spring MVC controller parameters annotated with @RequestBody where
 * the parameter type is a JPA @Entity or @Document class (domain entity used
 * directly as a DTO). This lets clients set any field including internal ones
 * like `id`, `role`, or `isAdmin`, bypassing application logic.
 *
 * Compliant:
 *   fun create(@RequestBody dto: CreateUserRequest): User  // dedicated DTO
 *
 * Non-compliant:
 *   fun create(@RequestBody user: User): User  // domain entity exposed directly
 */
class MassAssignmentRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MassAssignment",
        severity = Severity.Security,
        description = "@RequestBody bound to a domain entity — use a dedicated DTO to control exposed fields",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        function.valueParameters.forEach { param ->
            if (hasRequestBody(param) && typeIsEntity(param)) {
                reportAt(
                    param,
                    "Parameter '${param.name}' maps @RequestBody to a domain entity — use a DTO instead",
                )
            }
        }
    }

    private fun hasRequestBody(param: KtParameter) =
        param.annotationEntries.any { it.shortName?.asString() == DetectionPatterns.SPRING_REQUEST_BODY_ANNOTATION }

    @Suppress("ReturnCount")
    private fun typeIsEntity(param: KtParameter): Boolean {
        // Normalize: strip FQN, nullability, and generic type args so e.g.
        // `com.example.User?` and `User<T>` resolve to the simple name `User`.
        val typeName = param.typeReference?.text
            ?.substringAfterLast(".")
            ?.removeSuffix("?")
            ?.substringBefore("<")
            ?: return false
        val file = param.containingKtFile
        val cls = file.declarations
            .filterIsInstance<KtClass>()
            .firstOrNull { it.name == typeName }
            ?: return false
        return cls.annotationEntries.any { it.shortName?.asString() in DetectionPatterns.ENTITY_ANNOTATIONS }
    }
}
