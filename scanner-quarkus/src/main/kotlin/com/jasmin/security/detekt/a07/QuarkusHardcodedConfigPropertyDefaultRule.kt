package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A07 — Identification and Authentication Failures
// @ConfigProperty(defaultValue = "my-secret") embeds the secret in source code.
// If the env variable is absent the hardcoded default is silently used.
// Compliant:   @ConfigProperty(name = "jwt.secret")  // fail fast when absent
// Non-compliant: @ConfigProperty(name = "jwt.secret", defaultValue = "fallback-secret")
class QuarkusHardcodedConfigPropertyDefaultRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusHardcodedConfigPropertyDefault",
        severity = Severity.Security,
        description = "@ConfigProperty with hardcoded default for sensitive key — secret exposed in source code",
        debt = Debt.TEN_MINS,
    )

    private val sensitiveKeywords = setOf("secret", "password", "passwd", "apikey", "api_key", "token", "key")

    @Suppress("ReturnCount")
    override fun visitAnnotationEntry(annotation: KtAnnotationEntry) {
        super.visitAnnotationEntry(annotation)
        if (annotation.shortName?.asString() != "ConfigProperty") return
        val nameArg = annotation.valueArguments
            .find { it.getArgumentName()?.asName?.asString() == "name" }
            ?.getArgumentExpression()
        val nameText = (nameArg as? KtStringTemplateExpression)?.text?.trim('"')?.lowercase() ?: return
        if (sensitiveKeywords.none { it in nameText }) return
        val defaultArg = annotation.valueArguments
            .find { it.getArgumentName()?.asName?.asString() == "defaultValue" }
            ?.getArgumentExpression()
        val defaultText = (defaultArg as? KtStringTemplateExpression)?.text?.trim('"') ?: return
        if (defaultText.isBlank()) return
        reportAt(
            annotation,
            "@ConfigProperty defaultValue is a hardcoded secret for '$nameText' — " +
                "remove the default and ensure the property is always set in the environment",
        )
    }
}
