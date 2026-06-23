package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A03 — Injection / A02 — Cryptographic Failures
// Passing passwords, tokens, or secrets as URL query parameters exposes them in
// server logs, browser history, and HTTP Referer headers.
// Compliant:   pass credentials in the request body or Authorization header
// Non-compliant: fun login(@QueryParam("password") password: String)
class QuarkusSensitiveQueryParamRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusSensitiveQueryParam",
        severity = Severity.Security,
        description = "Sensitive data passed as @QueryParam — credentials in URLs end up in logs/history",
        debt = Debt.TEN_MINS,
    )

    private val sensitiveNames = setOf("password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "auth")

    // Split on non-alphanumeric boundaries AND camelCase boundaries, then lowercase, so a
    // sensitive word is matched as a whole token rather than a substring (e.g. "author"
    // tokenizes to [author] and does NOT match "auth"). Adjacent token pairs are also
    // joined so multi-word names like "apiKey"/"api_key" still match the "apikey" token.
    private fun tokenize(name: String): Set<String> {
        val camelSplit = name.replace(Regex("""(?<=[a-z0-9])(?=[A-Z])"""), " ")
        val parts = camelSplit.lowercase()
            .split(Regex("""[^a-z0-9]+"""))
            .filter { it.isNotEmpty() }
        val tokens = parts.toMutableSet()
        // Join adjacent parts so "apiKey" → "api" + "key" also yields "apikey".
        for (i in 0 until parts.size - 1) {
            tokens += parts[i] + parts[i + 1]
        }
        return tokens
    }

    @Suppress("ReturnCount")
    override fun visitAnnotationEntry(annotation: KtAnnotationEntry) {
        super.visitAnnotationEntry(annotation)
        if (annotation.shortName?.asString() != "QueryParam") return
        val paramName = annotation.valueArguments.firstOrNull()
            ?.getArgumentExpression()
            ?.let { (it as? KtStringTemplateExpression)?.text?.trim('"') } ?: return
        val tokens = tokenize(paramName)
        if (sensitiveNames.none { it in tokens }) return
        reportAt(
            annotation,
            "@QueryParam(\"$paramName\") — pass credentials in request body or Authorization header, not URL",
        )
    }
}
