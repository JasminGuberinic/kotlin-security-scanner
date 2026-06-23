package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A07 — Identification and Authentication Failures
// @Value("${jwt.secret:my-hardcoded-secret}") embeds a fallback secret in source code.
// Spring's @Value default syntax uses a SINGLE colon (the :- form is bash, not Spring).
// If the environment variable is absent, the hardcoded default is silently used.
// Compliant:   @Value("\${jwt.secret}") — fail-fast when env var is absent
// Non-compliant: @Value("\${jwt.secret:some-default}")
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
        // Spring @Value default syntax: @Value("${prop.name:default}") — a single ':' introduces a default.
        if ("\${" !in literal) return
        val placeholder = literal.substringAfter("\${").substringBefore("}")
        // No ':' means there is no default (e.g. ${jwt.secret}) — fail-fast, nothing to flag.
        if (":" !in placeholder) return
        val propName = placeholder.substringBefore(":").lowercase()
        val defaultValue = placeholder.substringAfter(":")
        if (sensitiveKeywords.none { it in propName }) return
        if (defaultValue.isBlank()) return
        reportAt(
            annotation,
            "@Value with default for sensitive property '$propName' — " +
                "remove the default and fail fast when the variable is absent",
        )
    }
}
