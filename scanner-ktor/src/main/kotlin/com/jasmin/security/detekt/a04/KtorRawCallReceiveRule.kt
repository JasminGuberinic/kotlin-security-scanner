package com.jasmin.security.detekt.a04

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A04 — Insecure Design
// call.receive<Any>() or call.receive<Map<*,*>>() bypasses type safety and
// accepts whatever the client sends. Combined with downstream reflection or
// deserialization, this becomes an RCE vector. Always deserialize into a
// specific, validated data class.
// Compliant:   call.receive<CreateUserRequest>()
// Non-compliant: call.receive<Any>()
class KtorRawCallReceiveRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorRawCallReceive",
        severity = Severity.Security,
        description = "call.receive<Any>() accepts untyped input — deserialize into a specific validated data class",
        debt = Debt.TWENTY_MINS,
    )

    private val unsafeTypes = setOf("Any", "HashMap", "Map", "LinkedHashMap", "MutableMap", "JsonElement", "JsonObject")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "receive") return
        val typeArg = expression.typeArguments.firstOrNull()?.text ?: return
        val baseType = typeArg.substringBefore("<").trim()
        if (baseType !in unsafeTypes) return
        reportAt(
            expression,
            "call.receive<$typeArg>() is unsafe — define a data class and use call.receive<YourRequest>() with validation",
        )
    }
}
