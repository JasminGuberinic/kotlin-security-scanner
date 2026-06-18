package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A07 — Identification and Authentication Failures
// A string literal assigned to a field named token/apiKey/secret embeds credentials
// in source code and build artifacts, trivially extractable via strings or decompilers.
// Compliant:   private val apiKey: String = System.getenv("API_KEY") ?: error("not set")
// Non-compliant: private val apiKey = "sk-prod-abc123"
class DropwizardHardcodedTokenRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardHardcodedToken",
        severity = Severity.Security,
        description = "Hardcoded credential assigned to sensitive field — use environment variable or Vault",
        debt = Debt.TWENTY_MINS,
    )

    private val sensitiveNames = setOf(
        "token", "apikey", "api_key", "apitoken", "secret", "password", "passwd",
        "credential", "bearertoken", "accesstoken", "refreshtoken",
    )

    @Suppress("ReturnCount")
    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)
        val nameLower = property.name?.lowercase() ?: return
        if (sensitiveNames.none { it in nameLower }) return
        val initializer = property.initializer as? KtStringTemplateExpression ?: return
        if (initializer.hasInterpolation()) return
        val value = initializer.text.trim('"')
        if (value.isBlank() || value.startsWith("\${")) return
        reportAt(property, "Hardcoded credential in '${property.name}' — load from environment or secret manager")
    }
}
