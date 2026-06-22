package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A07 — Identification and Authentication Failures
// @Value("\${jwt.secret:my-actual-secret}") embeds a fallback secret in source.
// If the env var is unset, the hardcoded default silently takes effect in production.
// Compliant:   @Value("\${jwt.secret}") — no default forces the app to fail fast
// Non-compliant: @Value("\${jwt.secret:hardcoded-secret}")
class MicronautHardcodedSecretRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautHardcodedSecret",
        severity = Severity.Security,
        description = "@Value property with hardcoded default for a secret — remove the default so the app fails fast",
        debt = Debt.TWENTY_MINS,
    )

    private val sensitiveNames = setOf(
        "secret", "password", "passwd", "pwd", "token", "apikey", "api-key",
        "api_key", "credential", "key", "jwt", "auth",
    )

    // Matches ${property.name:default} (Micronaut `:` separator, NOT Spring `:-`)
    private val valuePattern = Regex("""\$\{([^:}]+):(?!-)([^}]*)}""")

    @Suppress("ReturnCount")
    override fun visitAnnotationEntry(annotationEntry: KtAnnotationEntry) {
        super.visitAnnotationEntry(annotationEntry)
        if (annotationEntry.shortName?.asString() != "Value") return
        val valueExpr = annotationEntry.valueArguments.firstOrNull()
            ?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        val raw = valueExpr.rawValue()
        val match = valuePattern.find(raw) ?: return
        val propName = match.groupValues[1].lowercase()
        val default = match.groupValues[2]
        if (default.isBlank()) return
        if (sensitiveNames.none { it in propName }) return
        reportAt(
            annotationEntry,
            "@Value(\"\${$propName:***}\") has a hardcoded default — remove it so the app fails fast when the secret is absent",
        )
    }
}
