package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtParameter

// OWASP A08 — Software and Data Integrity Failures
// @RequestBody Any / @RequestBody Object allows Jackson to deserialize into any type
// at runtime, enabling deserialization gadget attacks (similar to CVE-2017-7525).
// Compliant:   fun update(@RequestBody dto: UpdateRequest)
// Non-compliant: fun update(@RequestBody body: Any)
class SpringBootRequestBodyAnyTypeRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringBootRequestBodyAnyType",
        severity = Severity.Security,
        description = "@RequestBody typed as Any/Object — enables polymorphic deserialization attacks",
        debt = Debt.TWENTY_MINS,
    )

    private val unsafeTypes = setOf("Any", "Object", "Serializable", "Comparable<*>")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val unsafeParam = function.valueParameters.firstOrNull { it.isUnsafeRequestBody() } ?: return
        reportAt(
            unsafeParam,
            "@RequestBody typed as ${unsafeParam.typeReference?.text} — use a concrete DTO class",
        )
    }

    private fun KtParameter.isUnsafeRequestBody(): Boolean {
        val hasRequestBody = annotationEntries.any { it.shortName?.asString() == "RequestBody" }
        if (!hasRequestBody) return false
        return typeReference?.text in unsafeTypes
    }
}
