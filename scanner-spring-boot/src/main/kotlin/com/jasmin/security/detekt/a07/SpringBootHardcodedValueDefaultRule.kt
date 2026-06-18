package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A07 — Identification and Authentication Failures
// @Value("${jwt.secret:-my-hardcoded-secret}") embeds a fallback secret in source code.
// If the environment variable is absent, the hardcoded default is silently used.
// Compliant:   @Value("\${jwt.secret}") — fail-fast when env var is absent
// Non-compliant: @Value("\${jwt.secret:-some-default}")
class SpringBootHardcodedValueDefaultRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringBootHardcodedValueDefault",
        severity = Severity.Security,
        description = "@Value with default secret — hardcoded fallback is used when env var is missing",
        debt = Debt.TEN_MINS,
    )

    private val sensitiveKeywords = setOf("secret", "password", "passwd", "apikey", "api_key", "token", "key")

    @Suppress("ReturnCount")
    override fun visitAnnotationEntry(annotation: KtAnnotationEntry) {
        super.visitAnnotationEntry(annotation)
        if (annotation.shortName?.asString() != "Value") return
        val valueArg = annotation.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val literal = (valueArg as? KtStringTemplateExpression)?.text?.trim('"') ?: return
        // @Value("${prop.name:-default}") — the :- introduces a default
        if (":-" !in literal) return
        val parts = literal.substringAfter("\${").split(":-")
        if (parts.size < 2) return
        val propName = parts[0].lowercase()
        val defaultValue = parts[1].trimEnd('}')
        if (sensitiveKeywords.none { it in propName }) return
        if (defaultValue.isBlank()) return
        reportAt(
            annotation,
            "@Value with default for sensitive property '$propName' — " +
                "remove the default and fail fast when the variable is absent",
        )
    }
}
