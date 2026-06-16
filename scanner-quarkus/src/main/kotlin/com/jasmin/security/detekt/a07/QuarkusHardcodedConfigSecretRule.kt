package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 * FindSecBugs: HARD_CODE_PASSWORD
 *
 * Flags @ConfigProperty fields where:
 *   - the `name` key contains a credential keyword (password, secret, token, …)
 *   - the `defaultValue` is a non-empty literal that doesn't look like a placeholder
 *
 * `defaultValue` in MicroProfile Config is used when no external config overrides the key.
 * Setting a real secret as the default effectively hardcodes it — anyone who forgets
 * to set the env var in production will silently use the baked-in value.
 *
 * Compliant:
 *   @ConfigProperty(name = "db.password")                      // fails fast if unset
 *   @ConfigProperty(name = "db.password", defaultValue = "")
 *
 * Non-compliant:
 *   @ConfigProperty(name = "db.password", defaultValue = "admin123")
 *   @ConfigProperty(name = "api.secret",  defaultValue = "s3cr3t")
 */
class QuarkusHardcodedConfigSecretRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusHardcodedConfigSecret",
        severity = Severity.Security,
        description = "@ConfigProperty with a credential key must not have a hardcoded defaultValue",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)

        val annotation = property.annotationEntries
            .firstOrNull { it.shortName?.asString() == "ConfigProperty" }
            ?: return

        val keyName = annotation.literalArg("name") ?: return
        val defaultVal = annotation.literalArg("defaultValue") ?: return

        if (isCredentialKey(keyName) && isHardcodedSecret(defaultVal)) {
            reportAt(property, buildMessage(keyName))
        }
    }

    private fun isCredentialKey(key: String): Boolean {
        val lower = key.lowercase()
        return DetectionPatterns.CREDENTIAL_VARIABLE_KEYWORDS.any { lower.contains(it) }
    }

    @Suppress("ReturnCount")
    private fun isHardcodedSecret(value: String): Boolean {
        if (value.isBlank()) return false
        return DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(value) }
    }

    private fun buildMessage(key: String) =
        "\"$key\" looks like a credential — remove the hardcoded defaultValue " +
            "so the app fails fast when the secret is not configured"
}

// valueArguments returns List<ValueArgument> (interface, no .text); use valueArgumentList instead
@Suppress("ReturnCount")
private fun KtAnnotationEntry.literalArg(name: String): String? {
    val expr = valueArgumentList?.arguments
        ?.firstOrNull { it.text.substringBefore("=").trim() == name }
        ?.getArgumentExpression() as? KtStringTemplateExpression
        ?: return null
    if (expr.hasInterpolation()) return null
    return expr.text.removeSurrounding("\"")
}
